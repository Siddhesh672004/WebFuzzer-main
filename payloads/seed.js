import mongoose from 'mongoose';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Payload } from '@smartfuzz/shared/models';
import { CURATED_PAYLOADS } from './curated.js';
import { parseWordlist, normalizeRecords, summarizeByType } from './wordlistParser.js';

// Seed script (PRD §8, Phase 1). Idempotent: re-running upserts by (type,value)
// so no duplicates accumulate. Always seeds the committed curated set; if the
// optional cloned wordlist repos are present (via setup.js), folds those in too.
//
// Run: `npm run seed`  (or `node payloads/seed.js`)

const __dirname = dirname(fileURLToPath(import.meta.url));

// Optional wordlist files to fold in when present. Each maps a cloned file to a
// payload type + metadata. Missing files are silently skipped (curated set is
// always enough to run).
const WORDLIST_SOURCES = [
  { file: 'seclists/Fuzzing/SQLi/Generic-SQLi.txt', type: 'sqli', source: 'seclists', categories: ['NUMERIC_ID', 'AUTH_FIELD', 'SEARCH_FIELD', 'GENERIC'], tags: ['error_based'] },
  { file: 'seclists/Fuzzing/XSS/XSS-Jhaddix.txt', type: 'xss', source: 'seclists', categories: ['SEARCH_FIELD', 'TEXT_FIELD', 'GENERIC'], tags: ['reflected'] },
  { file: 'seclists/Fuzzing/LFI/LFI-Jhaddix.txt', type: 'path_traversal', source: 'seclists', categories: ['FILE_PATH'], tags: ['lfi'] },
  { file: 'fuzzdb/attack/path-traversal/path-traversal-windows.txt', type: 'path_traversal', source: 'fuzzdb', categories: ['FILE_PATH'], tags: ['lfi', 'windows'] },
  { file: 'fuzzdb/attack/os-cmd-execution/command-injection-template.txt', type: 'cmd_injection', source: 'fuzzdb', categories: ['COMMAND'], tags: [] },
];

/**
 * Collect all payload records from the curated set plus any present wordlist
 * files. Pure-ish (only reads files); returns normalized, de-duped records.
 * @param {string} [baseDir] directory holding cloned wordlist repos
 */
export function collectPayloads(baseDir = __dirname) {
  const all = [...CURATED_PAYLOADS];

  for (const w of WORDLIST_SOURCES) {
    const path = join(baseDir, w.file);
    if (!existsSync(path)) continue;
    try {
      const raw = readFileSync(path, 'utf8');
      all.push(...parseWordlist(raw, w));
    } catch {
      // Unreadable file — skip, curated set still seeds.
    }
  }

  return normalizeRecords(all);
}

/**
 * Upsert payload records into Mongo idempotently. Returns counts.
 * @param {Array} records normalized payload records
 * @param {object} [model] Payload model (injectable for tests)
 */
export async function seedPayloads(records, model = Payload) {
  if (records.length === 0) return { upserted: 0, modified: 0, total: 0 };

  const ops = records.map((r) => ({
    updateOne: {
      filter: { type: r.type, value: r.value },
      update: {
        $set: { source: r.source, categories: r.categories, tags: r.tags, isActive: true },
        $setOnInsert: { type: r.type, value: r.value, successCount: 0 },
      },
      upsert: true,
    },
  }));

  const res = await model.bulkWrite(ops, { ordered: false });
  return {
    upserted: res.upsertedCount ?? 0,
    modified: res.modifiedCount ?? 0,
    total: await model.estimatedDocumentCount(),
  };
}

// CLI entry — only runs when invoked directly.
const isMain = process.argv[1] && process.argv[1].endsWith('seed.js');
if (isMain) {
  const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/smartfuzz';
  (async () => {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
    const { records, dropped } = collectPayloads();
    const summary = summarizeByType(records);
    const result = await seedPayloads(records);
    // eslint-disable-next-line no-console
    console.log(
      `[seed] ${records.length} payloads (${dropped} dropped) →`,
      `upserted ${result.upserted}, modified ${result.modified}, total ${result.total}`,
    );
    // eslint-disable-next-line no-console
    console.log('[seed] by type:', summary);
    await mongoose.disconnect();
  })().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[seed] failed:', err.message);
    process.exit(1);
  });
}
