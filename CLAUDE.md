# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

SmartFuzz is a zero-cost, fully-local web vulnerability scanner: email-OTP login, six scanning modules, CVSS v3.1 scoring, fix guidance, and rescan/comparison. See [README.md](README.md) for the product-level overview and a feature-by-feature breakdown.

## Commands

```bash
# Tests (Vitest everywhere; ESM, no transpile step)
npm test                                  # all workspaces
npm run test:worker                       # the scan engine — the correctness-critical core
npm run test:backend                      # API/auth/scan controllers
npm test --workspace worker -- crawler    # single test file by name substring
npx vitest run worker/test/cvss.test.js   # one file by path
npm run test:watch --workspace backend    # watch mode (defined per-workspace, not at root)

# Dev (each in its own terminal; needs Redis + Mongo up — `docker compose up redis mongo -d`)
npm run dev:backend       # node --env-file=.env --watch backend/src/server.js
npm run dev:worker        # node --env-file=.env --watch worker/src/index.js
npm run dev:frontend      # Vite dev server on :5173, proxies /api → :4000

# Full stack
docker compose up                         # frontend :5173, backend :4000, worker, redis, seed

# Payloads (curated set is committed and works out of the box; these are optional)
npm run setup:payloads    # shallow-clone SecLists/PayloadsAllTheThings/FuzzDB (data only)
npm run seed              # parse wordlists → MongoDB `payloads` collection

# E2E (requires the stack running)
npx playwright test       # from frontend/, one happy-path spec
```

**No linter is configured.** The root `lint` script uses `--if-present` and no workspace defines one — don't try to run or "fix" lint.

**Backend tests download a ~600MB MongoDB binary on first run** (`mongodb-memory-server`, `hookTimeout: 300000`) and run with `fileParallelism: false`. They force `MAIL_TRANSPORT=json` so no email is sent.

## Architecture

**npm-workspaces monorepo**: `shared`, `backend`, `worker`, `frontend`, `payloads`. All ESM (`"type": "module"`); Node 20.

The single most important structural fact: **the backend never scans, the worker does.** The backend owns HTTP (auth, REST, SSE) and *enqueues* jobs; the worker is a separate process that consumes them and runs the engine. They communicate only through Redis (BullMQ queues + pub/sub) and MongoDB.

```
frontend (React/nginx) ──HTTP──► backend (Express) ──BullMQ enqueue──► Redis ──► worker (ScanRunner + engine)
                       ◄──SSE──── backend ◄──pub/sub── Redis ◄──publishProgress── worker
                                              both read/write ──► MongoDB
```

### `shared/` is the contract layer — change it carefully
Both processes import `@smartfuzz/shared`. It exists so the two sides can't drift:
- `queues.js` — `QUEUES`/`JOBS` names. The backend enqueues and the worker consumes by these exact strings; a rename here that misses one side means jobs silently never run.
- `progress.js` — `progressChannel(id)` (the Redis channel) and `SSE_EVENTS` (`progress`/`finding`/`module`/`status`/`done`). Both ends must agree.
- `models/` — all Mongoose schemas (the DB shape for both reader and writer).
- `vulnTypes.js` / `cvssVectors.js` / `severity.js` — the vuln registry, canonical CVSS:3.1 vectors, and severity bands/penalties.
- `signatures.js` — `signature(type, endpoint, param)` = `sha1(type:normalizedPath:param)`, normalizing numeric/UUID/hex path segments to `:id`. **This is the stable cross-scan identity** that the comparison engine uses to label findings FIXED/PERSISTS/NEW/REGRESSED. Changing normalization breaks rescan continuity.

### Worker engine: pure functions with injectable dependencies
Every engine module ([worker/src/engine/](worker/src/engine/)) is a pure-ish function taking `http`, models, and a `publish` callback as injected deps — so the whole pipeline is testable **without Redis or network**. Tests use `nock`/fixtures and **never hit the live internet**; preserve that when adding detectors.

[scanRunner.js](worker/src/scan/scanRunner.js) is the orchestrator. Phase 1 crawls sequentially; Phase 2 runs passive/exposed/tech/fuzzer/auth concurrently, all sharing **one** `RateLimiter` and one `HttpClient`. Findings go through `makeFinding()` ([findingFactory.js](worker/src/engine/findingFactory.js)) — the single place a detection becomes a normalized record (severity + CVSS + OWASP ref + signature) — then deduped by signature and upserted.

**Note:** [worker/src/index.js](worker/src/index.js) registers a worker per module queue, but those handlers are still **placeholders** — the real work runs in `ScanRunner` on the single `orchestrate-queue`. The per-module queues and `PRIORITY` constants are a wired-but-unused fan-out seam.

### Non-negotiable invariants
- **Every outbound request goes through `HttpClient`** ([httpClient.js](worker/src/engine/httpClient.js)), which calls `assertSafeUrl()` ([urlGuard.js](worker/src/safety/urlGuard.js)) **first** and re-guards every redirect hop. This is the SSRF defense — don't add `axios`/`fetch` calls that bypass it. `SCAN_ALLOW_PRIVATE=true` is the only sanctioned way to reach localhost/RFC1918 (for the Dockerized DVWA/Juice Shop test targets).
- **CVSS uses the FIRST.org Appendix-A integer roundup** ([cvss.js](worker/src/scoring/cvss.js) `roundup()`), not `Math.ceil`, and handles scope-dependent PR. Don't "simplify" it — scores are spot-checked against NVD.
- **Adding a vuln type?** Add its CVSS vector in `shared/cvssVectors.js` **and** a fix guide in [worker/src/knowledge/fixGuides.js](worker/src/knowledge/fixGuides.js) — a CI test asserts every emittable type has a guide.
- **OTPs are bcrypt-hashed in Redis** ([otpStore.js](backend/src/services/otpStore.js)) with TTL/attempts/cooldown; the JWT lives in an httpOnly+`sameSite=strict` cookie. Auth is cookie-based (`withCredentials`), with a `Bearer` header fallback for tests.

### Config
Both backend and worker validate `process.env` with **zod** at startup and **fail fast** ([backend/src/config.js](backend/src/config.js), [worker/src/config.js](worker/src/config.js)). Dev loads `.env` via `node --env-file=.env`. The worker config is a deliberate subset (no JWT/mail/CORS).

# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.