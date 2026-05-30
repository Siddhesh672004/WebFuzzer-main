import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Optional setup: clone the upstream wordlist repos so seed.js can fold in the
// full payload corpus. SmartFuzz works WITHOUT this (the committed curated set
// is enough); this is for users who want maximum coverage.
//
// We use shallow, sparse clones to keep the download small. The repos are
// git-ignored (see .gitignore) — we only ever consume their text as data, never
// their code (THIRD_PARTY_NOTICES explains the licensing).
//
// Run: `npm run setup:payloads`  (or `node payloads/setup.js`)

const __dirname = dirname(fileURLToPath(import.meta.url));

const REPOS = [
  { dir: 'seclists', url: 'https://github.com/danielmiessler/SecLists.git', sparse: ['Fuzzing/SQLi', 'Fuzzing/XSS', 'Fuzzing/LFI', 'Fuzzing/RCE'] },
  { dir: 'payloadsallthethings', url: 'https://github.com/swisskyrepo/PayloadsAllTheThings.git', sparse: [] },
  { dir: 'fuzzdb', url: 'https://github.com/fuzzdb-project/fuzzdb.git', sparse: ['attack'] },
];

function run(cmd, args, cwd) {
  execFileSync(cmd, args, { cwd, stdio: 'inherit' });
}

function cloneRepo(repo, baseDir) {
  const dest = join(baseDir, repo.dir);
  if (existsSync(dest)) {
    // eslint-disable-next-line no-console
    console.log(`[setup] ${repo.dir} already present — skipping`);
    return;
  }
  // eslint-disable-next-line no-console
  console.log(`[setup] cloning ${repo.dir} (shallow)…`);

  if (repo.sparse.length > 0) {
    run('git', ['clone', '--depth', '1', '--filter=blob:none', '--sparse', repo.url, dest]);
    run('git', ['sparse-checkout', 'set', ...repo.sparse], dest);
  } else {
    run('git', ['clone', '--depth', '1', repo.url, dest]);
  }
  // eslint-disable-next-line no-console
  console.log(`[setup] ${repo.dir} ready`);
}

const isMain = process.argv[1] && process.argv[1].endsWith('setup.js');
if (isMain) {
  const baseDir = __dirname;
  if (!existsSync(baseDir)) mkdirSync(baseDir, { recursive: true });
  try {
    for (const repo of REPOS) cloneRepo(repo, baseDir);
    // eslint-disable-next-line no-console
    console.log('\n[setup] done. Now run `npm run seed` to load payloads into MongoDB.');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[setup] failed:', err.message);
    console.error('[setup] SmartFuzz still works with the built-in curated payloads.');
    process.exit(1);
  }
}

export { REPOS, cloneRepo };
