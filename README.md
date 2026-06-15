# SmartFuzz 🛡️

> A zero-cost, fully local, intelligent web vulnerability scanner.
> Final Year Project — Sinhgad College of Engineering, Pune.

SmartFuzz gives students, junior developers, and small teams a Burp Suite–level
scanning experience at **zero cost**, with a clean, modern, hacker-themed UI.
You verify by email OTP, paste a target URL, and SmartFuzz crawls it, runs six
scanning modules, CVSS-scores every finding, generates step-by-step fix guidance,
and lets you rescan and compare the results over time — all running locally via Docker.
It sharpens its attack payloads with **context-aware AI generation (the free Google
Gemini tier)** and falls back to a fully-local curated library when offline — so it
stays **zero-cost** either way.

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
- [What's new in v0.2 (the upgrade)](#whats-new-in-v02-the-upgrade-)
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
  plus an **active multi-request detector stage** (IDOR / JWT `alg:none` / session
  fixation), all coordinated by one orchestrator behind a shared rate limiter.
- **Live progress** streamed to the browser over Server-Sent Events (SSE): progress
  %, per-module status, and findings as they're confirmed.
- **CVSS v3.1 scoring** computed with the FIRST.org Appendix-A integer roundup
  (scope-dependent privileges handled correctly), mapped to severity bands and a
  0–100 security score.
- **42 vulnerability types** across the OWASP Top 10 (2021), each with a CVSS vector and a
  fix guide (a CI test enforces 1:1 coverage so no type can ship without guidance).
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

## What's new in v0.2 (the upgrade) 🚀

This release closes the gap between SmartFuzz's *registry* (the list of things it
knows about) and its *active detection* (the things it can actually prove), adds an
opt-in browser crawler and AI payload generation, upgrades the reports, and gives the
whole app a redesigned look. Everything below is **on by default unless marked
opt-in**, and nothing here requires a paid API or breaks the "works offline" promise.

If you're new to the project, think of each item as "a new thing SmartFuzz can now
find or do."

### 🔎 More vulnerabilities it can actually confirm

The fuzzer and a new **active-detector** stage now confirm classes that were
previously only catalogued:

- **SSRF (Server-Side Request Forgery)** — when a parameter like `?url=` / `?content=`
  / `?fetch=` makes the server fetch a URL *you* supply. SmartFuzz only flags it with
  **proof** (cloud-metadata content or an internal-service banner echoed back), so it
  doesn't cry wolf on a plain `200 OK`. A big latency spike on an internal address is
  surfaced as a "possible blind SSRF" lead rather than a false finding.
- **IDOR (Insecure Direct Object Reference)** — tries neighbouring IDs on numeric URL
  parameters (`?id=5` → `4`, `6`, `999999`) and flags when another user's record comes
  back, with a "manual verification recommended" note.
- **JWT `alg:none`** — if the app uses a JSON Web Token in a cookie, SmartFuzz forges an
  unsigned (`alg:none`) copy and replays it. If the server accepts it, that's a critical
  auth bypass.
- **XXE (XML External Entity)** — posts crafted XML to body-accepting endpoints and
  confirms when the server leaks a file (`/etc/passwd`-class content).
- **Verbose-error / stack-trace disclosure** — a payload that triggers an HTTP 500 with
  a Java / Python / PHP / .NET / **Spring** stack trace is recorded as an information
  leak (paths, framework, versions).
- **Time-based command injection** — a `; sleep 5` / `ping` payload that delays the
  response confirms blind RCE even when nothing is echoed back; Windows command output
  (`COMPUTERNAME=`) is now recognised too.
- **Session fixation** (opt-in via Aggressive mode) plus the already-present **NoSQL /
  LDAP / XPath / CRLF** detectors are now wired into every scan path.

### 🌐 Headless (browser) crawler — *opt-in*

Modern single-page apps (React/Vue/Angular) build their links and forms with
JavaScript, so a plain HTML crawler sees almost nothing. Enable
`SCAN_HEADLESS_CRAWLER=true` (or tick **Headless crawl** in Advanced options) and
SmartFuzz drives a real headless browser to render the page, discover JS-built routes,
and capture the XHR/fetch API calls the app makes. It reuses the **Puppeteer/Chromium
already bundled for screenshots** — no new ~300 MB dependency — and automatically falls
back to the fast static crawler if anything goes wrong.

### 🔐 Authenticated crawl — *opt-in*

Scan the pages behind a login. Three modes, configured on the New Scan page:
- **cookie** — paste a session cookie string;
- **headers** — paste custom headers (e.g. `Authorization: Bearer …`);
- **form_fill** — give a login URL + field names + credentials and the headless crawler
  logs in for you. **The password is never stored in the database** — it travels only in
  the transient scan job and is discarded after the crawl. Captured session cookies are
  shared with every other module so the whole scan runs authenticated.

### 🤖 AI payload generation — *opt-in, off by default*

Set `AI_PAYLOAD_MODE=gemini` (free Google Gemini API key) or `ollama` (a fully-local
model — no key, no internet) and SmartFuzz asks the model for a few extra,
context-aware payloads tuned to each parameter, *on top of* the deterministic curated
set (it never replaces it). A **circuit breaker** trips on rate-limit (HTTP 429) and
falls back to curated-only, so a free quota can't stall a scan. An **adaptive second
pass** re-tests confirmed critical/high findings with AI escalation variants. With the
default `AI_PAYLOAD_MODE=off`, none of this runs and no network is touched.

### ⚠️ Aggressive mode toggle

Intrusive checks (real default-credential login attempts, session-fixation probes) are
now **off by default** and gated behind an explicit **Aggressive mode** switch with a
warning — so a routine scan never submits login attempts to a target you don't fully
control.

### 📊 Benchmark page + API

A new **Benchmark** page (`/benchmark`, API `GET /api/benchmark/stats`) shows your
coverage at a glance: scans run, findings, vuln-types seen vs. detectable, average
security score, a findings-by-type breakdown, a severity distribution, the score trend,
and a documented **SmartFuzz vs OWASP ZAP** capability comparison.

### 📄 Richer reports

Every generated report (HTML / PDF / JSON / Markdown) now includes:
- an **Authorization & Legal Consent** page (operator, timestamp, IP, the three consent
  statements, and the IT Act 2000 / CFAA / Computer Misuse Act references);
- a **Disclaimer & Methodology** section;
- a **deduplication audit** (raw payload firings → unique findings, dedup rate, and the
  signing algorithm);
- **aggregate CVSS** headline figures (highest + average CVSS) in the executive summary
  and on the results page.

Reports are also **cache-invalidated** now: if a scan's data changes (e.g. after a
verify-fix re-test) the report is rebuilt automatically, and `DELETE /api/reports/:scanId`
forces a fresh build.

### 🎯 Demo mode + more knowledge

- **Demo mode** (`SMARTFUZZ_DEMO_MODE=true`) pre-fills the New Scan page with an
  authorized public test target and shows a banner — handy for a live walkthrough.
- The **sensitive-paths** list grew to **200+** entries and the **CVE database** to
  **25+** technology families (now including Ruby on Rails).

### 🎨 The "Phosphor" interface + a public landing page

The original hacker-terminal identity is back, rebuilt properly. The whole UI runs on
a perceptually-uniform **OKLCH** token system: green-tinted terminal blacks (never flat
`#000`), one **phosphor-green** signature accent (brand, primary action, focus, live
state), and semantic severity colours that mirror the CVSS bands so risk reads
instantly. Type is **Space Grotesk** for display, **Geist** for body text, and
**JetBrains Mono** (ligatures disabled, so `--flag` never renders as an em-dash) for
data that *is* code: payloads, URLs, CVSS vectors, scores.

Motion follows design-engineering discipline: UI animations stay under 300ms on custom
ease-out curves, only `transform`/`opacity` ever animate, pressables give instant
`scale(0.97)` feedback, hover effects are gated to real pointers, and everything
collapses gracefully under `prefers-reduced-motion`. Signature touches are reserved for
moments that mean something: a blinking terminal cursor, CRT scanlines over log panels,
and a soft phosphor glow on the brand and primary actions.

There is also a new **public landing page** at `/`: an auto-typed terminal replay of a
real scan (module-by-module output, severity-coloured findings, final score), a
seven-cell module grid, scoring and rescan-comparison showcases, and the safety
engineering, all scroll-revealed with staggered entrances. It stays fast on a poor
connection: route-based code-splitting (the landing chunk is ~8 kB gzip), virtualized
lists, and GPU-only animations.

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
├── IMPLEMENTATION_PLAN.md        # phased TDD build plan
├── THIRD_PARTY_NOTICES.md        # data-source & clean-room attribution
│
├── shared/                       # contract layer (no network, no Express)
│   └── src/
│       ├── models/               # User, Target, Scan, Endpoint, Vulnerability, Payload, Report
│       ├── severity.js           # bands, ranks, score penalties, severityFromScore()
│       ├── vulnTypes.js          # 42-type registry mapped to OWASP Top 10
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
├── frontend/                     # React + Vite SPA ("Phosphor" terminal theme)
│   ├── nginx.conf                # SPA fallback + /api proxy with SSE tuning
│   ├── tailwind.config.js        # OKLCH token system: surfaces, accent, severity
│   └── src/
│       ├── main.jsx  App.jsx     # bootstrap + routes
│       ├── api/                  # client (axios), scans
│       ├── hooks/                # useAuth (React Query), useMediaQuery
│       ├── lib/                  # palette (chart hex mirror), vulnLabels
│       ├── components/           # ProtectedRoute, Layout, BottomNav, ScanTerminal,
│       │                         #   VulnerabilityCard/DetailSheet, gauges, charts,
│       │                         #   ui primitives (Button/Input/Alert/Badge/…)
│       └── pages/                # Landing, Verify, Dashboard, NewScan, ScanMonitor,
│                                 #   ScanResults, FixGuide, Comparison, Reports,
│                                 #   Benchmark
│
└── payloads/                     # payload library
    ├── curated.js                # curated built-in payloads (works out of the box)
    ├── setup.js                  # optional: shallow-clone SecLists/PATT/FuzzDB
    ├── wordlistParser.js         # parse cloned wordlists → payload records
    └── seed.js                   # upsert payloads into MongoDB
```

---

## User flow

Step-by-step, mapped to page components and API calls:

0. **Landing** (`/` → [Landing.jsx](frontend/src/pages/Landing.jsx)) — the public page:
   animated terminal scan replay, the seven modules, scoring/comparison showcases, and
   the safety story. "Launch console" / "Start scanning" route into the app (via
   `/verify` when unauthenticated). No API calls.
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
   Each finding links to a full-screen **fix guide** (`/fix/:scanId/:vulnId` →
   [FixGuide.jsx](frontend/src/pages/FixGuide.jsx)) with before/after code and one-click
   fix re-verification.
6. **Comparison** (`/compare/:domain` →
   [Comparison.jsx](frontend/src/pages/Comparison.jsx)) — `GET /api/scans/target/:domain`.
   Score-trend chart + per-scan summary table.
7. **Reports** (`/reports` → [Reports.jsx](frontend/src/pages/Reports.jsx)) — lists
   completed scans with HTML/PDF/CSV/Markdown download buttons
   (`GET /api/reports/:scanId/<format>`, fetched as a blob).
8. **Benchmark** (`/benchmark` → [Benchmark.jsx](frontend/src/pages/Benchmark.jsx)) —
   `GET /api/benchmark/stats`. Coverage metrics, findings-by-type, severity distribution,
   score trend, and a documented SmartFuzz-vs-OWASP-ZAP comparison.
9. **Logout** — `POST /api/auth/logout` clears the cookie and bounces to `/verify`.

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
emits `status: running`, then **Phase 1** runs the crawler sequentially (static, or the
opt-in headless browser crawler; also collecting same-host `<script src>` JS URLs);
**Phase 2** runs passive, exposed, tech, fuzzer, auth, the JS secret scanner, and the
active multi-request detectors (IDOR / JWT / session-fixation) — all sharing **one**
`RateLimiter` and one `HttpClient` so concurrency can't DoS the target. An optional
adaptive AI second pass then re-tests confirmed critical/high findings (no-op unless
`AI_PAYLOAD_MODE` is set). Each module's findings are normalized by
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
| 3 | **Exposed files** | [exposedFiles.js](worker/src/engine/exposedFiles.js) | Probes 200+ sensitive paths (`.env`, `.git/HEAD`, `/admin`, `/actuator`, swagger, backups, …) | **mandatory soft-404 detection** via two random control paths + content fingerprint before flagging |
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
  (`uid=…(` **and** time-based `sleep`/`ping`, Windows `COMPUTERNAME=`), SSTI
  (`{{7*7}}`→`49`), open redirect (cross-origin `Location`), **SSRF** (cloud-metadata /
  internal-banner proof), **NoSQL / LDAP / XPath / CRLF** injection, **XXE** (file
  disclosure via XML body), and **stack-trace disclosure** on a payload-induced HTTP 500
  (Java/Python/PHP/.NET/Spring). Anomalies (other 500s, ±20% body, 3× latency) return
  `interest: HIGH/MEDIUM` to trigger mutation.
- **Active (multi-request) detectors** ([activeDetectors.js](worker/src/engine/activeDetectors.js)
  + [activeScan.js](worker/src/engine/activeScan.js)) run a dedicated stage that can't be
  decided from one response: **IDOR** (neighbour-ID enumeration), **JWT `alg:none`**
  (forge-and-replay), and **session fixation** (login-boundary cookie rotation, gated by
  Aggressive mode).
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
| [shared/src/vulnTypes.js](shared/src/vulnTypes.js) | 42-type registry keyed to OWASP Top 10 (2021) |
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
| [worker/src/knowledge/fixGuides.js](worker/src/knowledge/fixGuides.js) | 42 fix guides (what/why/steps/before/after/verify), one per emittable type |
| [worker/src/knowledge/cveDatabase.js](worker/src/knowledge/cveDatabase.js) | Curated local tech→CVE map (jQuery, Bootstrap, lodash, WordPress, Drupal, PHP, Apache, nginx, OpenSSL, …) |
| [payloads/curated.js](payloads/curated.js) | Curated built-in payloads (SQLi/XSS/SSRF/NoSQL/XXE/LDAP/CRLF/…) so scans work with zero setup |
| [frontend/nginx.conf](frontend/nginx.conf) | SPA fallback + `/api` proxy tuned for SSE (`proxy_buffering off`, 3600s read timeout) |

---

## External integrations

SmartFuzz makes **no paid-API calls** — detection runs against the target, bundled
local data, and the **free Google Gemini tier** for AI payload generation (which
degrades to the local curated library when no key is set or the quota is hit). The
one heavier optional dependency is a headless Chromium (Puppeteer) for screenshot
evidence, which is **off by default**.

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
- **AI payload generation (Gemini-powered, on by default)** — `AI_PAYLOAD_MODE=gemini`
  (the shipped default) calls the free Google Gemini REST API for context-aware
  payloads; `=ollama` calls a local Ollama server (no internet); `=off` disables it
  entirely. If no `GEMINI_API_KEY` is set or the free quota is hit, the engine
  transparently falls back to curated payloads, so scans never fail and offline use is
  unaffected. The worker config still *defaults* to `off`, so CI/grading run key-free.
  Implemented over plain HTTP (no SDK dependency) with a 429 circuit breaker.
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
| **Headless crawl** *(opt-in)* | `SCAN_HEADLESS_CRAWLER` (false), `HEADLESS_MAX_PAGES` (20), `HEADLESS_TIMEOUT_MS` (15000), `PUPPETEER_EXECUTABLE_PATH` (shared with screenshots) |
| **AI payloads** *(opt-in)* | `AI_PAYLOAD_MODE` (off\|gemini\|ollama), `GEMINI_API_KEY`, `GEMINI_MODEL` (gemini-2.0-flash-lite), `OLLAMA_BASE_URL`, `OLLAMA_MODEL` (mistral), `AI_PAYLOAD_RATE_LIMIT_COOLDOWN_MS` (120000), `AI_PAYLOAD_MAX_PER_TYPE` (5) |
| **Demo mode** | `SMARTFUZZ_DEMO_MODE` (false), `SMARTFUZZ_DEMO_TARGET` (`http://testphp.vulnweb.com`) |
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

Honest assessment of where the codebase stands today (after the v0.2 upgrade above).

**Resolved in v0.2** (kept here so older notes don't mislead): per-module BullMQ fan-out
is now a real, Redis-coordinated path (`WORKER_FANOUT=true`); the dormant detectors (SSRF,
IDOR, JWT `alg:none`, XXE, NoSQL/LDAP/XPath/CRLF, stored-XSS, session-fixation,
stack-trace disclosure, time-based RCE) are now wired and confirmable; the sensitive-paths
list is 200+; default-credential probing is gated behind Aggressive mode; an opt-in
headless crawler handles SPAs; `recharts`/`framer-motion`/`react-virtual` are wired; and
reports are cache-invalidated. 

**Remaining limitations:**

- **Rate limiter is per-process.** In `WORKER_FANOUT` mode the fan-out jobs share one
  rate limiter *within a worker process* (via the per-scan context cache). Running
  **multiple** worker replicas would need a Redis-backed token bucket to keep the shared
  rate-limit invariant across processes.
- **CVE database is curated, not exhaustive.** ~25 tech families with a couple of CVEs
  each, by design (zero external calls at scan time). It demonstrates the
  detect-version→match-CVE pipeline; an offline NVD snapshot would be the scale-up path.
  The tech *fingerprinter* also doesn't yet recognise every family the CVE map covers
  (e.g. a `rails` CVE entry exists, but Rails fingerprinting is limited).
- **AI / headless / authenticated crawl are opt-in and unverified in CI.** They're
  off by default and exercised by unit tests with mocked backends; they aren't part of the
  automated end-to-end run (which stays offline and browser-free). A live Gemini/Ollama
  key or a real Chromium is needed to use them for real.
- **IDOR & blind-SSRF are advisory by nature.** Object-level authorization and blind SSRF
  can't be fully auto-proven; those findings carry a "manual verification recommended"
  note rather than hard proof.
- **Benchmark precision is coverage-based, not ground-truth.** True precision/recall needs
  labelled datasets we don't have at runtime, so the Benchmark page reports measurable
  facts (coverage, distribution, trend) and a *documented* ZAP comparison — it does not
  fabricate a precision percentage.
- **TypeScript migration not done.** The frontend is JSX/JS (the optional P6.3 TS pass was
  out of scope for this release).

---

## License

MIT — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution of all
open-source data sources (SecLists, PayloadsAllTheThings, FuzzDB) and clean-room
references (OWASP ZAP, Wapiti, Nikto). SmartFuzz bundles no third-party scanner code and
makes no runtime API calls.
