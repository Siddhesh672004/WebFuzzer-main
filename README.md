# SmartFuzz 🛡️

> A zero-cost, fully local, intelligent web vulnerability scanner.
> Final Year Project — Sinhgad College of Engineering, Pune.

SmartFuzz gives students, junior developers, and small teams a Burp Suite–level
scanning experience at **zero cost**, with a clean, modern, hacker-themed UI.
You verify by email OTP, paste a target URL, and SmartFuzz crawls it, runs six
scanning modules, CVSS-scores every finding, generates step-by-step fix guidance,
and lets you rescan and compare results over time — all running locally via Docker,
**with no paid AI APIs and no cloud dependency**.

---

## ⚠️ Authorized use only

SmartFuzz is an active security scanner. **Only scan systems you own or have
explicit written permission to test.** Unauthorized scanning may be illegal under
the IT Act 2000 (India), the Computer Fraud and Abuse Act (US), and equivalent laws
elsewhere. Every scan requires an in-app authorization confirmation, which is logged
(user ID, timestamp, IP, user-agent) on the `Scan.consent` record. Safe practice
targets: DVWA, OWASP WebGoat, OWASP Juice Shop, bWAPP.

---

## Table of contents

- [What SmartFuzz does](#what-smartfuzz-does)
- [Tech stack](#tech-stack)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [User flow](#user-flow)
- [Behind the scenes — what happens on each action](#behind-the-scenes--what-happens-on-each-action)
- [Data flow](#data-flow)
- [The scan engine in depth](#the-scan-engine-in-depth)
- [Scoring, reports & comparison](#scoring-reports--comparison)
- [Safety engineering](#safety-engineering)
- [Data model](#data-model)
- [Key files and their roles](#key-files-and-their-roles)
- [External integrations](#external-integrations)
- [Quick start](#quick-start)
- [Environment variables](#environment-variables)
- [Tests](#tests)
- [Current limitations & areas for improvement](#current-limitations--areas-for-improvement)
- [License](#license)

---

## What SmartFuzz does

**Purpose.** Most students and small teams can't afford Burp Suite Pro or Acunetix,
and free tools either only scan (no scoring/guidance) or require expert setup.
SmartFuzz closes that gap: one URL in, a CVSS-scored vulnerability report with
copy-paste fix guidance out — and a history that shows whether your fixes actually
worked on the next scan.

**Core features.**

- **Email-OTP login** — no passwords stored; a 6-digit code, then a JWT in an
  httpOnly cookie.
- **One-click scan** with an explicit authorization gate (logged for audit).
- **Seven scanning modules** — crawler, passive analyzer, exposed-file scanner, tech
  fingerprinter, active payload fuzzer, auth tester, and a JavaScript secret scanner —
  coordinated by one orchestrator behind a shared rate limiter.
- **Live progress** streamed to the browser over Server-Sent Events (SSE): progress
  %, per-module status, and findings as they're confirmed.
- **CVSS v3.1 scoring** computed with the FIRST.org Appendix-A integer roundup
  (scope-dependent privileges handled correctly), mapped to severity bands and a
  0–100 security score.
- **39 vulnerability types** across the OWASP Top 10 (2021), each with a fix guide.
- **Exposed-secret detection** — fetches every same-host JavaScript file the crawler
  finds and scans it for ~38 secret patterns (AWS/Google/Stripe/GitHub keys, DB
  connection strings, private keys, JWTs, hardcoded passwords). Only a masked preview
  (first 8 chars + `****`) is ever stored — never the full secret.
- **Screenshot evidence (opt-in)** — for confirmed XSS / open-redirect findings, a
  headless Chromium (Puppeteer) captures a browser screenshot as visual proof. Off by
  default (`SCAN_SCREENSHOTS`); SSRF-guarded before navigation.
- **Step-by-step fix guidance** — what/why/how, before & after code, and a verify step.
- **Rescan & compare** — every finding gets a stable signature so SmartFuzz can label
  it `FIXED` / `PERSISTS` (VULNERABLE) / `NEW` / `REGRESSED` across scans and chart the
  security-score trend.
- **Professional reports in five formats** — JSON, standalone HTML, CSV, Markdown, and
  PDF. The HTML/PDF layouts are a full pen-test report: cover page, executive summary,
  risk matrix, per-finding detail (incl. masked secrets + screenshots), and remediation
  guidance. PDF is rendered with **pdfkit** (pure-JS, no headless browser).

**Real-world use cases.**

- A student demonstrating OWASP Top-10 concepts against DVWA/Juice Shop for a viva.
- A junior dev sanity-checking a side project before deploying.
- A small team tracking whether last sprint's security fixes held up.
- A security course needing a safe, offline, reproducible scanner that never touches
  the live internet during tests.

---

## Tech stack

| Layer    | Tech |
|----------|------|
| Frontend | React 18, Vite 5, Tailwind 3.4, React Router 6, React Query 5 (`@tanstack/react-query`), Recharts, Framer Motion, Lucide icons, `@tanstack/react-virtual` |
| Backend  | Node 20 LTS, Express 4, Mongoose 8, BullMQ 5, ioredis, Nodemailer, jsonwebtoken, bcryptjs, zod, helmet, cors, cookie-parser, express-rate-limit, pino / pino-http |
| Worker   | Node 20, BullMQ 5, Mongoose 8, axios, cheerio, ipaddr.js, pdfkit, Puppeteer (opt-in screenshots), pino |
| Data     | MongoDB 7 (Mongoose ODM), Redis 7 (BullMQ queues + OTP store + pub/sub) |
| Testing  | Vitest, supertest, mongodb-memory-server, nock, Testing Library, Playwright |
| Infra    | Docker + Docker Compose, nginx (static serving + API/SSE proxy) |

This is an **npm-workspaces monorepo**: `shared`, `backend`, `worker`, `frontend`,
`payloads`. The scan engine is **custom code** — SmartFuzz bundles no third-party
scanner binaries and makes **no runtime API calls**. Open-source wordlists (SecLists,
PayloadsAllTheThings, FuzzDB) are consumed as *data*; OWASP ZAP passive-scan regexes
were ported clean-room to JS.

---

## Architecture

```
┌──────────────┐   HTTPS    ┌─────────────────────────┐  enqueue   ┌──────────┐
│  frontend    │ ─────────► │  backend                │ ─────────► │  Redis   │
│ React + Vite │            │  Express REST + SSE      │  (BullMQ)  │  BullMQ  │
│ (nginx)      │ ◄───SSE──── │  auth · scans · reports │ ◄──pub/sub─┤  pub/sub │
└──────────────┘            └───────────┬─────────────┘            └────┬─────┘
                                        │ read/write                    │ consume
                                        ▼                               ▼
                                  ┌───────────┐               ┌──────────────────┐
                                  │  MongoDB  │ ◄──────────── │  worker          │
                                  │ (Mongoose)│  write        │  ScanRunner +    │
                                  └───────────┘  findings     │  7 scan modules  │
                                                              └──────────────────┘
```

- **backend** — owns HTTP: OTP auth, REST, SSE streaming, enqueues scan jobs. **Never
  scans.** Subscribes to Redis pub/sub to relay worker progress to the browser.
- **worker** — a separate process running BullMQ workers + the scan engine
  (crawl / fingerprint / fuzz / analyze / score). Publishes progress to Redis.
- **frontend** — static React SPA served by nginx, which also proxies `/api` (and the
  SSE stream) to the backend.
- **MongoDB** — users, targets, scans, endpoints, vulnerabilities, payloads, reports.
- **Redis** — BullMQ job queues, OTP + cooldown storage, scan-rate counters, and the
  `scan:progress:<id>` pub/sub channel that powers live updates.

**How the pieces connect.** The `shared` workspace is the contract layer: it owns the
Mongoose models, the BullMQ queue/job names (so backend-enqueue and worker-consume can
never drift), the SSE event names and channel function, the vuln-type registry, CVSS
vectors, severity bands, and the finding-signature function. Both backend and worker
import from `@smartfuzz/shared`; the frontend imports only the non-Mongoose bits.

---

## Repository layout

```
smartfuzz/
├── docker-compose.yml            # redis, backend, worker, seed, frontend
├── docker-compose.testing.yml    # DVWA, WebGoat, Juice Shop, bWAPP (--profile testing)
├── .env.example                  # every env var, documented
├── package.json                  # workspaces + root scripts
├── SmartFuzz_PRD.md              # product spec (v3.0)
├── IMPLEMENTATION_PLAN.md        # phased TDD build plan
├── SmartFuzz_Project_Context.md  # constraints & rationale
├── THIRD_PARTY_NOTICES.md        # data-source & clean-room attribution
│
├── shared/                       # contract layer (no network, no Express)
│   └── src/
│       ├── models/               # User, Target, Scan, Endpoint, Vulnerability, Payload, Report
│       ├── severity.js           # bands, ranks, score penalties, severityFromScore()
│       ├── vulnTypes.js          # 39-type registry mapped to OWASP Top 10
│       ├── cvssVectors.js        # canonical CVSS:3.1 vector per type/subtype
│       ├── signatures.js         # stable cross-scan signature (sha1)
│       ├── queues.js             # QUEUES, JOBS, PRIORITY constants
│       └── progress.js           # progressChannel(), SSE_EVENTS
│
├── backend/                      # Express API + SSE
│   └── src/
│       ├── server.js  app.js  config.js  logger.js
│       ├── controllers/          # auth, scan, report
│       ├── routes/               # auth, scan, report, screenshots, health
│       ├── middleware/           # auth (JWT), error (AppError)
│       ├── services/             # mailer (Nodemailer), otpStore (Redis+bcrypt)
│       └── lib/                  # db, redis, queue, jwt
│
├── worker/                       # BullMQ workers + the scan engine
│   └── src/
│       ├── index.js              # registers a worker per queue + the orchestrator
│       ├── scan/                 # scanRunner.js (orchestrator), publisher.js (SSE)
│       ├── engine/               # crawler, httpClient, passiveAnalyzer, exposedFiles,
│       │                         #   techFingerprinter, paramClassifier, payloadEngine,
│       │                         #   payloadFuzzer, responseAnalyzer, mutationEngine,
│       │                         #   authTester, jsSecretScanner, findingFactory
│       ├── services/             # screenshotCapture (Puppeteer, opt-in)
│       ├── safety/               # urlGuard (SSRF), rateLimiter (token bucket)
│       ├── scoring/              # cvss, securityScore, comparison, reportGenerator
│       └── knowledge/            # cveDatabase, fixGuides, sensitivePaths
│
├── frontend/                     # React + Vite SPA
│   ├── nginx.conf                # SPA fallback + /api proxy with SSE tuning
│   └── src/
│       ├── main.jsx  App.jsx     # bootstrap + routes
│       ├── api/                  # client (axios), scans
│       ├── hooks/useAuth.js      # React Query auth state
│       ├── components/           # ProtectedRoute, ui (Button/Input/Alert)
│       └── pages/                # Verify, Dashboard, NewScan, ScanMonitor,
│                                 #   ScanResults, Comparison, Reports
│
└── payloads/                     # payload library
    ├── curated.js                # 59 built-in payloads (works out of the box)
    ├── setup.js                  # optional: shallow-clone SecLists/PATT/FuzzDB
    ├── wordlistParser.js         # parse cloned wordlists → payload records
    └── seed.js                   # upsert payloads into MongoDB
```

---

## User flow

Step-by-step, mapped to page components and API calls:

1. **Verify** (`/verify` → [Verify.jsx](frontend/src/pages/Verify.jsx)) — enter email →
   `POST /api/auth/send-otp`. In dev the response carries `devOtp` / `previewUrl` hints.
   Enter the 6-digit code → `POST /api/auth/verify-otp` → backend sets the httpOnly JWT
   cookie → redirect to the page you came from (or `/dashboard`).
2. **Dashboard** (`/dashboard` → [Dashboard.jsx](frontend/src/pages/Dashboard.jsx)) —
   `GET /api/scans` (polls every 10s). Stats cards + recent-scans table; click a row to
   monitor (running) or view results (completed).
3. **New scan** (`/scan/new` → [NewScan.jsx](frontend/src/pages/NewScan.jsx)) — enter a
   target URL, tick the authorization consent box → `POST /api/scans` → redirect to the
   monitor.
4. **Live monitor** (`/scan/:id` → [ScanMonitor.jsx](frontend/src/pages/ScanMonitor.jsx))
   — opens `new EventSource('/api/scans/:id/progress')` and renders `progress`,
   `module`, `finding`, and `done` events in real time, with a `GET /api/scans/:id` poll
   every 3s as a fallback.
5. **Results** (`/results/:id` → [ScanResults.jsx](frontend/src/pages/ScanResults.jsx)) —
   `GET /api/scans/:id` + `GET /api/scans/:id/vulnerabilities`. Security score, severity
   filter, and expandable findings (param, CVSS vector, payload, evidence, OWASP ref).
6. **Comparison** (`/compare/:domain` →
   [Comparison.jsx](frontend/src/pages/Comparison.jsx)) — `GET /api/scans/target/:domain`.
   Score-trend chart + per-scan summary table.
7. **Reports** (`/reports` → [Reports.jsx](frontend/src/pages/Reports.jsx)) — lists
   completed scans with HTML/PDF/CSV/Markdown download buttons
   (`GET /api/reports/:scanId/<format>`, fetched as a blob).
8. **Logout** — `POST /api/auth/logout` clears the cookie and bounces to `/verify`.

All routes except `/verify` are wrapped in
[ProtectedRoute.jsx](frontend/src/components/ProtectedRoute.jsx), which checks
`useAuth()` (`GET /api/auth/me`) and redirects unauthenticated users to `/verify`,
preserving the intended destination.

---

## Behind the scenes — what happens on each action

**Sending an OTP** (`POST /api/auth/send-otp`,
[auth.controller.js](backend/src/controllers/auth.controller.js)):
zod validates/normalizes the email → `isOnCooldown(email)` checks a Redis key
(`otp:cooldown:<email>`, 429 if active) → `createOtp(email)` generates a 6-digit code
via `crypto.randomInt`, **bcrypt-hashes it**, stores `{hash, attempts}` at
`otp:<email>` with a TTL, and sets the cooldown key → `sendOtpEmail()` delivers it via
Nodemailer (Ethereal in dev, Gmail in prod). The plaintext OTP is never stored or logged.

**Verifying an OTP** (`POST /api/auth/verify-otp`):
`verifyOtp()` bcrypt-compares the submitted code, decrementing remaining attempts on
mismatch and deleting the record on success or after `OTP_MAX_ATTEMPTS` (default 3) →
`User.findOneAndUpdate({email}, …, {upsert:true})` finds-or-creates the user →
`signToken(user)` issues a JWT (`{sub, email}`) → `res.cookie()` sets it httpOnly,
`sameSite=strict`, `secure` in prod, 7-day maxAge.

**Creating a scan** (`POST /api/scans`,
[scan.controller.js](backend/src/controllers/scan.controller.js)):
zod requires `authorized === true` (the consent gate) → derives `origin`/`domain` from
the URL → `Target.findOneAndUpdate(… $inc:{scanCount:1} …, {upsert:true})` atomically
allocates the per-target `scanNumber` → `Scan.create()` stores config + a `consent`
audit snapshot (IP, user-agent, timestamp) → `enqueueScan()`
([lib/queue.js](backend/src/lib/queue.js)) adds a `start-scan` job to the
`orchestrate-queue` → returns the scan (201).

**Running a scan** (worker, [scanRunner.js](worker/src/scan/scanRunner.js)):
the `ORCHESTRATE` worker in [index.js](worker/src/index.js) builds a `ScanRunner`. It
emits `status: running`, then **Phase 1** runs the crawler sequentially (also collecting
same-host `<script src>` JS URLs); **Phase 2** runs passive, exposed, tech, fuzzer, auth,
and the JS secret scanner — all sharing **one** `RateLimiter` and one `HttpClient` so
concurrency can't DoS the target. Each module's findings are normalized by
`makeFinding()`, deduped by signature, and upserted into the `Vulnerability` collection;
the `Scan` doc's progress/stats are updated and a `done` event is emitted. When
`SCAN_SCREENSHOTS=true`, confirmed XSS / open-redirect findings additionally trigger a
non-blocking Puppeteer screenshot (see Safety engineering).

**Watching progress** (`GET /api/scans/:id/progress`):
after ownership check, the backend sets SSE headers, subscribes a *duplicate* Redis
connection to `scan:progress:<id>`, and forwards every published event to the browser
as `event: <kind>\ndata: <json>`. A 15s heartbeat (`: ping`) keeps proxies from closing
the stream; `X-Accel-Buffering: no` and nginx's `proxy_buffering off` keep it flowing.

**Downloading a report** (`GET /api/reports/:scanId/<format>`,
[report.controller.js](backend/src/controllers/report.controller.js)):
`getOrBuildReport()` returns a cached `Report` or builds one — pulls the scan's vulns
plus all prior completed scans of the same domain, calls `buildReportJson()` (which
enriches each finding with its fix guide and runs the comparison engine), caches the
JSON + pre-rendered HTML, then serializes to the requested format
(`buildReportHtml/Csv/Markdown/Pdf`).

---

## Data flow

```
URL + consent ─► POST /api/scans ─► Scan(pending) in Mongo ─► BullMQ "start-scan" job
      │                                                              │
      ▼                                                              ▼
 ScanRunner.run()                                          ┌── crawl(targetUrl) ──┐  Phase 1 (sequential)
      │   one shared RateLimiter + HttpClient (SSRF-guarded)│   endpoints + JS URLs│
      │                                                     │   → Mongo            │
      │                                                     └──────────┬───────────┘
      │   Phase 2 (concurrent):                                        ▼
      ├── analyzePassive(headers/body) ───────────────► findings ─┐
      ├── scanExposedFiles(soft-404 aware) ───────────► findings ─┤
      ├── fingerprint() → matchCves() ────────────────► findings ─┤  makeFinding()
      ├── fuzzEndpoint() → analyzeResponse() ──────────► findings ─┤  → severity + CVSS
      │      └─ HIGH_INTEREST → mutate() → re-fuzz                 │  → signature
      ├── testAuth(rate-limit, default creds) ─────────► findings ─┤  → dedupe → Mongo
      └── scanJsSecrets(JS files) ────────────────────► findings ─┘  (masked previews)
      │
      ▼   publishProgress() ─► Redis "scan:progress:<id>" ─► backend SSE ─► browser
      ▼
 Scan(completed) + stats (counts, securityScore) ─► Report on demand (JSON/HTML/CSV/MD/PDF)
                                                          │
                          compareScans() vs prior scans ──┘ → FIXED/PERSISTS/NEW/REGRESSED
```

**Input → processing → output.** A target URL and consent flag become a queued job.
The worker turns it into discovered endpoints, fired payloads, and analyzed responses;
each confirmed issue becomes a normalized `Vulnerability` (severity, CVSS score+vector,
evidence, OWASP ref, stable signature). Counts roll up into a 0–100 security score.
A report stitches findings + fix guides + cross-scan comparison into downloadable
artifacts. Throughout, progress flows worker → Redis → backend → browser over SSE.

---

## The scan engine in depth

The seven engine modules map to these files, all orchestrated by
[scanRunner.js](worker/src/scan/scanRunner.js):

| # | Module | File | What it does | Technique |
|---|--------|------|--------------|-----------|
| 1 | **Crawler** | [crawler.js](worker/src/engine/crawler.js) | BFS same-host crawl up to `maxDepth`/`maxEndpoints`; extracts links, forms, query params, and `<script src>` JS URLs | cheerio HTML parsing; URL normalization (fragment stripped, params sorted) |
| 2 | **Passive analyzer** | [passiveAnalyzer.js](worker/src/engine/passiveAnalyzer.js) | Findings from a normal response: missing HTTPS/HSTS/CSP/X-Frame/X-Content-Type, version disclosure, CORS `*`, insecure cookies, stack-trace/internal-IP/email leakage | header inspection + body regexes (ZAP-ported) |
| 3 | **Exposed files** | [exposedFiles.js](worker/src/engine/exposedFiles.js) | Probes 32 sensitive paths (`.env`, `.git/HEAD`, `/admin`, `/actuator`, …) | **mandatory soft-404 detection** via two random control paths + content fingerprint before flagging |
| 4 | **Tech fingerprinter** | [techFingerprinter.js](worker/src/engine/techFingerprinter.js) | Detects framework/server/library + version, then matches the **local CVE database** | header/cookie/meta/path/JS-filename patterns → `matchCves(tech, version)` |
| 5 | **Payload fuzzer** | [payloadFuzzer.js](worker/src/engine/payloadFuzzer.js) | Active injection: classify params → load payloads → baseline → fire → analyze → mutate HIGH_INTEREST hits | see classifier/engine/analyzer/mutation below |
| 6 | **Auth tester** | [authTester.js](worker/src/engine/authTester.js) | On pages with a password field: brute-force-protection check (20 rapid POSTs; expects 429/403) and 6 default-credential combos | response-based success heuristics |
| 7 | **JS secret scanner** | [jsSecretScanner.js](worker/src/engine/jsSecretScanner.js) | Fetches each same-host JS file the crawler found and scans the raw source for ~38 secret patterns (cloud keys, DB URIs, private keys, JWTs, passwords) | regex library; line-number + masked-preview extraction, dedupe by pattern+prefix; **stores only `first-8-chars + ****`** |

The fuzzer is itself a small pipeline:

- **`classifyParam(name, inputType)`** ([paramClassifier.js](worker/src/engine/paramClassifier.js))
  maps a parameter to a category (`NUMERIC_ID`, `SEARCH_FIELD`, `FILE_PATH`, `URL_FIELD`,
  `AUTH_FIELD`, `COMMAND`, …) and an ordered list of attack types (e.g. `NUMERIC_ID →
  ['sqli','idor']`, `FILE_PATH → ['path_traversal','ssrf']`).
- **`loadPayloads(attackTypes, {cap})`** ([payloadEngine.js](worker/src/engine/payloadEngine.js))
  queries the `Payload` collection for active payloads of the mapped vuln types, sorted
  by `successCount` (historically effective first). `recordSuccess()` bumps a payload's
  counter when it confirms a finding — a feedback loop that prioritizes what works.
- **`analyzeResponse(baseline, response, meta)`** ([responseAnalyzer.js](worker/src/engine/responseAnalyzer.js))
  applies ZAP-ported detection rules: SQL error signatures, **time-based SQLi** (response
  > 2× baseline, ≥5s), reflected XSS (unencoded echo), LFI (`root:x:0:0`), RCE
  (`uid=…(`), SSTI (`{{7*7}}`→`49`), open redirect (cross-origin `Location`). Anomalies
  (HTTP 500, ±20% body, 3× latency) return `interest: HIGH/MEDIUM` to trigger mutation.
- **`mutate(payload, attackType)`** ([mutationEngine.js](worker/src/engine/mutationEngine.js))
  generates WAF-bypass variants (comment-spacing, case toggling, URL/entity encoding,
  tag/function swaps, `../` obfuscation) — chased ahead of fresh payloads.
- **`makeFinding(f)`** ([findingFactory.js](worker/src/engine/findingFactory.js)) is the
  single place a detection becomes a record: it pulls the CVSS vector from
  `@smartfuzz/shared/cvssVectors`, derives severity, attaches the OWASP ref, and computes
  the cross-scan signature.

Every outbound request goes through **`HttpClient`**
([httpClient.js](worker/src/engine/httpClient.js)): SSRF-guarded first, rate-limited,
body-capped (2 MB), time-bounded (10s), with manual redirect-following that re-guards
each hop (max 5).

---

## Scoring, reports & comparison

- **CVSS v3.1** ([cvss.js](worker/src/scoring/cvss.js)) — `computeCvss(vector)` implements
  the FIRST.org base-score formula with the **Appendix-A integer-arithmetic roundup**
  (`roundup()`, not `Math.ceil`) and scope-dependent privilege weights, so scores
  spot-check against NVD. Canonical vectors live in
  [cvssVectors.js](shared/src/cvssVectors.js) (e.g. `sqli` = 10.0 `S:C`, `cmd_injection`
  = 9.8, reflected vs stored XSS split into subtype vectors).
- **Security score** ([securityScore.js](worker/src/scoring/securityScore.js)) — `100 −
  Σ(count × penalty)`, floored at 0. Penalties: critical 20, high 10, medium 5, low 2,
  informational 0 ([severity.js](shared/src/severity.js)).
- **Comparison engine** ([comparison.js](worker/src/scoring/comparison.js)) — `compareScans()`
  diffs vuln sets across a target's scans by **signature**, labeling each
  `VULNERABLE` (persists) / `FIXED` / `NEW` / `REGRESSED`; `comparisonSummary()` rolls
  those up for the latest scan.
- **Signatures** ([signatures.js](shared/src/signatures.js)) — `sha1(type : normalizedPath :
  param)`, where the path normalizer collapses numeric/UUID/hex segments to `:id`. This
  stable identity is what makes "did my fix hold?" answerable across scans.
- **Reports** ([reportGenerator.js](worker/src/scoring/reportGenerator.js)) —
  `buildReportJson()` enriches findings with fix guides + comparison, then
  `buildReportHtml` and `buildReportPdf` render a professional pen-test report (cover
  page, executive summary, risk matrix, findings-by-type, per-finding detail incl.
  masked secrets + screenshot notes, remediation guidance), while `buildReportCsv` and
  `buildReportMarkdown` produce the lightweight formats. The PDF uses **pdfkit**
  (pure-JS, no headless browser) so report generation stays deterministic and
  dependency-light.

---

## Safety engineering

SmartFuzz is built to be safe to run and safe to operate against authorized targets:

- **SSRF target guard** ([urlGuard.js](worker/src/safety/urlGuard.js)) — `assertSafeUrl()`
  rejects non-http(s) schemes and any host resolving (via DNS) to private, loopback,
  link-local (incl. `169.254.169.254` cloud metadata), unique-local, reserved,
  broadcast, or CGNAT ranges using `ipaddr.js`. Re-checked on **every redirect hop**.
  `SCAN_ALLOW_PRIVATE=true` is the explicit, opt-in escape hatch for local lab targets.
- **Shared rate limiter** ([rateLimiter.js](worker/src/safety/rateLimiter.js)) — a
  token-bucket (`take()`/`tryTake()`) shared across all modules of a scan, default
  10 req/s, so "seven modules at once" can't become a flood.
- **Consent gate + audit** — `POST /api/scans` requires `authorized: true`; the
  `Scan.consent` subdocument records user, timestamp, IP, and user-agent.
- **Resource caps** — per-request timeout, per-scan wall-clock budget
  (`SCAN_WALLCLOCK_BUDGET_MS`), 2 MB body cap, crawler depth/endpoint ceilings.
- **Soft-404 detection** before flagging any exposed file, to suppress false positives
  on servers that 200 everything.
- **Masked secrets, never stored raw** — the JS secret scanner stores only a
  `first-8-chars + ****` preview of any matched credential; the full secret value never
  touches the database or the report.
- **Screenshot capture is opt-in and SSRF-guarded** — disabled unless
  `SCAN_SCREENSHOTS=true`. When enabled, `assertSafeUrl()` validates the proof URL
  *before* Puppeteer launches, and capture runs fully non-blocking so it can never delay
  or fail a scan. Note: Puppeteer runs Chromium with `--no-sandbox` and navigates
  attacker-influenced URLs, so only enable it against authorized targets.
- **SmartFuzz protecting itself** — helmet, strict CORS to `FRONTEND_ORIGIN`,
  rate-limited auth routes (30 req / 15 min / IP), zod validation on every input, JWT in
  an httpOnly + `sameSite=strict` cookie, the screenshot route's filename allowlist +
  path-traversal guard, pino redaction of secrets/tokens, and no secrets shipped to the
  client.

---

## Data model

MongoDB collections (Mongoose schemas in [shared/src/models/](shared/src/models/)):

- **User** — `email` (unique), `lastLoginAt`, `totalScans`. OTP-only; no password hash.
- **Target** — groups scans per `userId`+`domain`; `scanCount` drives `scanNumber`.
- **Scan** — `status` (`pending|running|completed|failed|cancelled`), nested `config`,
  `progress` (with a `moduleStatus` map), `stats` (severity counts + `securityScore` +
  timing), and a required `consent` audit subdocument.
- **Endpoint** — discovered URL+method with classified `params[]` and a captured
  `baselineResponse`; unique per `scanId`+`url`+`method`.
- **Vulnerability** — the finding: `type`, `subtype`, `severity`, `cvssScore`,
  `cvssVector`, `url`, `param`, `payload`, `evidence`, `owaspRef`, `cveId`, inline
  `request`/`response` proof, and the stable `signature` (unique per `scanId`).
  `isFixed` is flipped by the comparison engine on rescans. Exposed-secret findings add
  `secretType`/`jsFileUrl`/`lineNumber`/`matchPreview` (masked); XSS/open-redirect
  findings may add `screenshotFile`/`screenshotDialogFired`/`screenshotDialogMessage`.
- **Payload** — `source` (seclists/payloadsallthethings/fuzzdb/nikto/custom), `type`,
  `value`, `categories[]`, `tags[]`, `successCount` (for prioritization), `isActive`.
- **Report** — denormalized snapshot of a completed scan: `summary`, `comparison`,
  `topFindings`, full `jsonContent`, and pre-rendered `htmlContent`.

---

## Key files and their roles

| File | Role |
|------|------|
| [shared/src/queues.js](shared/src/queues.js) | `QUEUES`/`JOBS`/`PRIORITY` — the single source of truth both processes agree on |
| [shared/src/progress.js](shared/src/progress.js) | `progressChannel(id)` + `SSE_EVENTS` (`progress`, `finding`, `module`, `status`, `done`) |
| [shared/src/vulnTypes.js](shared/src/vulnTypes.js) | 39-type registry keyed to OWASP Top 10 (2021) |
| [shared/src/cvssVectors.js](shared/src/cvssVectors.js) | Canonical CVSS:3.1 vector + expected score per type/subtype |
| [backend/src/app.js](backend/src/app.js) | Express factory: helmet → cors → json → cookies → pino → routes → error handlers |
| [backend/src/controllers/scan.controller.js](backend/src/controllers/scan.controller.js) | Scan create/list/get/delete + the SSE progress endpoint |
| [backend/src/routes/screenshots.routes.js](backend/src/routes/screenshots.routes.js) | Auth-guarded `/api/screenshots/:filename` — serves screenshot evidence PNGs with filename allowlist + traversal guard |
| [backend/src/services/otpStore.js](backend/src/services/otpStore.js) | Redis-backed, bcrypt-hashed OTP with attempts + cooldown |
| [backend/src/lib/queue.js](backend/src/lib/queue.js) | `enqueueScan()` → BullMQ `start-scan` job |
| [worker/src/index.js](worker/src/index.js) | Registers a worker per queue + the orchestrator handler |
| [worker/src/scan/scanRunner.js](worker/src/scan/scanRunner.js) | The orchestrator: runs all seven modules, persists findings, emits progress, fires opt-in screenshots |
| [worker/src/engine/jsSecretScanner.js](worker/src/engine/jsSecretScanner.js) | Scans crawled JS files for ~38 secret patterns; masks every match (`first-8 + ****`) |
| [worker/src/services/screenshotCapture.js](worker/src/services/screenshotCapture.js) | Puppeteer screenshot evidence (opt-in via `SCAN_SCREENSHOTS`, SSRF-guarded, lazy import) |
| [worker/src/engine/httpClient.js](worker/src/engine/httpClient.js) | The single guarded, rate-limited, capped outbound client |
| [worker/src/scoring/cvss.js](worker/src/scoring/cvss.js) | CVSS v3.1 calculator with Appendix-A roundup |
| [worker/src/knowledge/fixGuides.js](worker/src/knowledge/fixGuides.js) | 39 fix guides (what/why/steps/before/after/verify), one per emittable type |
| [worker/src/knowledge/cveDatabase.js](worker/src/knowledge/cveDatabase.js) | Curated local tech→CVE map (jQuery, Bootstrap, lodash, WordPress, Drupal, PHP, Apache, nginx, OpenSSL, …) |
| [payloads/curated.js](payloads/curated.js) | 59 built-in payloads so scans work with zero setup |
| [frontend/nginx.conf](frontend/nginx.conf) | SPA fallback + `/api` proxy tuned for SSE (`proxy_buffering off`, 3600s read timeout) |

---

## External integrations

SmartFuzz makes **no paid-API and no cloud calls during a scan** — detection runs
entirely against the target and bundled local data. The one heavier optional dependency
is a headless Chromium (Puppeteer) for screenshot evidence, which is **off by default**.

- **Email (Nodemailer)** — the only outbound integration. **Ethereal** (throwaway SMTP,
  logs a preview URL) in dev; **Gmail** SMTP via `GMAIL_USER` + `GMAIL_APP_PASSWORD` in
  prod; a `json` transport in tests.
- **Headless Chromium (Puppeteer, opt-in)** — used only for screenshot evidence when
  `SCAN_SCREENSHOTS=true`. Imported lazily, so the default build/tests never require
  Chromium; the Docker worker image installs the system Chromium via `apk`. Navigates the
  target itself (no third-party service), SSRF-guarded first.
- **Open-source wordlists (data, not runtime)** — `payloads/setup.js` can shallow/sparse-
  clone **SecLists**, **PayloadsAllTheThings**, and **FuzzDB**; `seed.js` parses them
  into the `Payload` collection. SmartFuzz works without this via the committed curated
  set.
- **OWASP ZAP pscanrules (reference, not runtime)** — passive-scan regexes were ported
  clean-room to JS; no ZAP code is bundled. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Local CVE database** — `matchCves()` runs against the bundled
  [cveDatabase.js](worker/src/knowledge/cveDatabase.js); there is **no NVD API call** at
  scan time.
- **Dockerized test targets** (dev only) — `docker-compose.testing.yml` brings up DVWA
  (`:8080`), WebGoat (`:8081`), Juice Shop (`:8082`), bWAPP (`:8083`) under
  `--profile testing`.

---

## Quick start

```bash
# 1. Configure
cp .env.example .env
#   edit .env — set JWT_SECRET; in dev, MAIL_TRANSPORT=ethereal needs no email setup

# 2. Bring up the full stack
docker compose up

# 3. (Optional) load the full wordlist corpus — the curated set already works
npm run setup:payloads   # clones SecLists/PayloadsAllTheThings/FuzzDB (data only)
npm run seed             # parses wordlists into the `payloads` collection
```

App: http://localhost:5173 · API: http://localhost:4000

### Local development (without Docker for the app code)

```bash
npm install                 # installs all workspaces
docker compose up redis -d  # Redis for queues/OTP; point MONGO_URI at local or Atlas
npm run dev:backend         # terminal 1
npm run dev:worker          # terminal 2
npm run dev:frontend        # terminal 3
```

### Testing against vulnerable targets

```bash
docker compose -f docker-compose.yml -f docker-compose.testing.yml --profile testing up
# then set SCAN_ALLOW_PRIVATE=true in .env to scan http://dvwa (etc.)
```

---

## Environment variables

Grouped by purpose (see [.env.example](.env.example) for full defaults):

| Group | Vars |
|-------|------|
| **Server** | `NODE_ENV`, `PORT` (4000), `FRONTEND_ORIGIN` |
| **Data** | `MONGO_URI`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` |
| **Auth / JWT** | `JWT_SECRET`, `JWT_EXPIRES_IN` (7d), `AUTH_COOKIE_NAME` |
| **OTP** | `OTP_TTL_SECONDS` (600), `OTP_MAX_ATTEMPTS` (3), `OTP_RESEND_COOLDOWN_SECONDS` (60) |
| **Mail** | `MAIL_TRANSPORT` (ethereal\|gmail\|json), `MAIL_FROM`, `GMAIL_USER`, `GMAIL_APP_PASSWORD` |
| **Scan safety** | `SCAN_RATE_LIMIT` (10), `SCAN_MAX_DEPTH` (3), `SCAN_MAX_ENDPOINTS` (500), `SCAN_REQUEST_TIMEOUT_MS` (10000), `SCAN_WALLCLOCK_BUDGET_MS` (1800000), `SCAN_MAX_BODY_BYTES` (2097152), `SCAN_ALLOW_PRIVATE` (false) |
| **Screenshots** | `SCAN_SCREENSHOTS` (false — opt-in Puppeteer evidence), `SCREENSHOT_DIR` (`/tmp/smartfuzz-screenshots`; shared worker↔backend volume), `PUPPETEER_EXECUTABLE_PATH` (set to system Chromium in Docker) |
| **Worker** | `WORKER_FUZZ_CONCURRENCY` (5), `WORKER_FANOUT` (false) |
| **Logging** | `LOG_LEVEL` (info) |

Both backend and worker validate their env with **zod** at startup and **fail fast** on
bad config.

---

## Tests

```bash
npm test                    # all workspaces
npm run test:worker         # just the engine (the correctness-critical core)
npm run test:backend        # API + auth + scan controllers (supertest + in-memory Mongo)
npm run test:frontend       # React components (Testing Library)
```

The scan engine is tested against **mocked** HTTP responses (nock / fixtures), never the
live internet — deterministic, safe, and fast. The frontend ships one Playwright happy-
path E2E ([happy-path.spec.js](frontend/e2e/happy-path.spec.js)).

---

## Current limitations & areas for improvement

Honest assessment of where the codebase stands today:

- **Per-module queues are wired but not used for fan-out.** `index.js` registers a worker
  for each of the six module queues, but those handlers are still **placeholders** — the
  real work runs inside `ScanRunner` on the single `orchestrate-queue`. The PRD's
  "six independent queues firing simultaneously" is an architectural seam that isn't
  fully realized; modules run concurrently *within one job* via `Promise`, not as
  distributed jobs. Adaptive `PRIORITY` (mutations jumping the queue) is defined in
  `shared/queues.js` but not yet exercised end-to-end.
- **Detection breadth vs. the registry.** 39 vuln *types* and CVSS vectors are defined,
  but several (XXE, stored XSS confirmation, session fixation, JWT `alg:none`, NoSQL/LDAP/
  XPath injection) are catalogued without full active detectors yet. The fuzzer's
  confirmed detectors center on SQLi, XSS, path traversal, RCE, SSTI, and open redirect;
  the passive, exposed-file, tech-fingerprint, auth, and JS-secret modules cover the rest.
- **Sensitive-paths list is 32 entries**, not the "150+" the PRD aspired to —
  easy to extend in [sensitivePaths.js](worker/src/knowledge/sensitivePaths.js).
- **CVE database is illustrative.** ~10 tech families with one or two CVEs each, by design
  (zero external calls). It demonstrates the detect-version→match-CVE pipeline rather than
  providing exhaustive coverage; an offline NVD snapshot would be the upgrade path.
- **Auth tester sends real default-credential POSTs** (admin/admin, etc.). That's
  intentional for authorized testing, but it's intrusive — worth gating behind an
  "aggressive" toggle.
- **Crawler is static-HTML only** (cheerio). SPAs/JS-rendered routes and APIs behind
  client-side routing won't be discovered without a headless-browser crawler.
- **Frontend libraries partially unused.** `recharts`, `framer-motion`, and
  `@tanstack/react-virtual` are bundled (and chunk-split) but not yet wired into the
  pages — opportunities for the score-trend chart, animations, and virtualized finding
  lists the PRD calls for.
- **Reports are built on demand and cached**, but there's no regeneration/invalidation if
  a scan's data changes after the first report build.
- **Scaling.** Single worker process by default; horizontal scaling would need queue
  fan-out (above) and care around the per-scan in-memory `RateLimiter`, which is local to
  a process.

---

## License

MIT — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution of all
open-source data sources (SecLists, PayloadsAllTheThings, FuzzDB) and clean-room
references (OWASP ZAP, Wapiti, Nikto). SmartFuzz bundles no third-party scanner code and
makes no runtime API calls.
