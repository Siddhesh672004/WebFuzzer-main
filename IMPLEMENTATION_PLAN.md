# SmartFuzz — Implementation Plan

## Build Blueprint, TDD Strategy & Engineering Decisions

> Companion document to `SmartFuzz_PRD.md` (v3.0)
> Version 1.0 | Final Year Project | Sinhgad College of Engineering, Pune
> Status: **Greenfield** — repository currently contains only design docs. Zero code implemented.

---

## Table of Contents

1. [How to Read This Document](#1-how-to-read-this-document)
2. [Locked Decisions (Read First)](#2-locked-decisions-read-first)
3. [Research Findings That Shape the Build](#3-research-findings-that-shape-the-build)
4. [Architecture Decisions & Rationale](#4-architecture-decisions--rationale)
5. [Definitive Tech Stack (with versions)](#5-definitive-tech-stack-with-versions)
6. [Monorepo Layout](#6-monorepo-layout)
7. [Test-Driven Development Strategy](#7-test-driven-development-strategy)
8. [Phase-by-Phase Implementation Plan](#8-phase-by-phase-implementation-plan)
9. [The Scanning Engine — Module Contracts](#9-the-scanning-engine--module-contracts)
10. [Safety Engineering (Critical)](#10-safety-engineering-critical)
11. [Edge Cases & How We Handle Each](#11-edge-cases--how-we-handle-each)
12. [Frontend Performance Plan (Lazy Loading)](#12-frontend-performance-plan-lazy-loading)
13. [Definition of Done — Per Feature](#13-definition-of-done--per-feature)
14. [Risk Register](#14-risk-register)
15. [What to Demo to the Examiner](#15-what-to-demo-to-the-examiner)

---

## 1. How to Read This Document

The PRD (`SmartFuzz_PRD.md`) says **what** SmartFuzz is and **what** it does. This document says **how** we build it, **in what order**, **how we test it**, and **what could go wrong**. Every claim in here that touches money, licensing, or correctness has been verified against a primary source — those are footnoted in Section 3.

If you read only one section before we start coding, read **Section 2 (Locked Decisions)** and **Section 10 (Safety Engineering)**. The first prevents rework; the second prevents the project from being a liability.

---

## 2. Locked Decisions (Read First)

These three were ambiguous in the original docs. They are now resolved and the entire plan assumes them.

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | **Scanning engine** | **Custom Node.js engine** — we write our own crawler, fuzzer, and analyzer. Payloads come from cloned wordlists (SecLists/FuzzDB); detection regexes are ported from OWASP ZAP rules. We do **not** shell out to ZAP/Nikto/Nuclei at runtime. | Originality is graded. A wrapper around existing scanners invites the "you just called someone else's tool" critique. Owning the engine is the engineering contribution. |
| 2 | **User verification** | **Email OTP, no password.** Email → 6-digit code via free Gmail SMTP → JWT in httpOnly cookie. Redis holds the OTP with a 10-min TTL. | A security tool storing passwords is ironic and adds reset-flow surface. OTP is lighter, demoable, and free. |
| 3 | **This deliverable** | **Docs first.** Refined PRD + this plan. Code begins only after your approval. | One review checkpoint now saves days of rebuilding later. |

**Standing constraints (non-negotiable):**
- Zero cost. Free at build time and at runtime. No paid API, no subscription, no cloud dependency during a scan.
- Fully offline after one-time payload seeding.
- Lightweight on **both** ends. Frontend bundle stays small; backend stays within a modest RAM/CPU footprint so it runs on a laptop.
- Hacker-themed dark UI, fully responsive (mobile + tablet + desktop), lazy-loaded throughout.
- TDD — tests written alongside (often before) implementation.

---

## 3. Research Findings That Shape the Build

Everything below was verified against primary sources during the research pass. These are the facts the build depends on.

### 3.1 Licensing — all five sources are safe to use & redistribute for free

| Source | License | Verdict for our project |
|---|---|---|
| **SecLists** | MIT | ✅ Clone, embed, redistribute. Keep the copyright notice. |
| **PayloadsAllTheThings** | MIT | ✅ Same as above. |
| **FuzzDB** | BSD-style + CC-BY-3.0 + Apache-2.0 + MIT (mixed) | ✅ Redistributable **with attribution**. Preserve notices. |
| **OWASP ZAP `pscanrules`** | Apache-2.0 | ✅ We **port the regex patterns/heuristics** to JS (clean-room). Add an Apache-2.0 NOTICE attribution. |
| **Wapiti** | GPL v2 | ⚠️ **Study-only.** We read its source for architectural ideas and re-implement in Node from scratch. We do **not** copy or link its code, so GPL does not reach our codebase. Cite it as a reference, not a dependency. |

**Action item baked into Phase 1:** create a `THIRD_PARTY_NOTICES.md` listing every source, its license, and our usage. Examiners love seeing license hygiene; it signals professional maturity.

### 3.2 CVSS v3.1 — the PRD's pre-calculated scores are correct

Verified by recomputing from the official FIRST.org formula:

- SQL Injection `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → **10.0** ✓
- Reflected XSS `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → **6.1** ✓
- SSRF `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N` → **9.3** ✓

**Two correctness rules we must follow in code (these are the common bugs):**
1. **Roundup must use the integer-arithmetic algorithm from the spec's Appendix A**, *not* `Math.ceil(x*10)/10`. Naive rounding is off by 0.1 on float-representation edge cases — a spot-check against NVD would expose it.
2. **Privileges Required (PR) is scope-dependent.** When Scope is **Changed**, PR:L = 0.68 and PR:H = 0.5 (not 0.62 / 0.27). Implementing PR as unconditional under-scores every scope-changed vector.

**Report-writing note:** CVSS **v4.0** was published 2023-11-01 and is the current FIRST standard. We implement **v3.1** deliberately — it's still what NVD and most scanners use, and its base equations are simpler and well-documented. Say exactly that in the report; do **not** call v3.1 "the latest."

### 3.3 Free infrastructure facts

| Item | Verified fact | Consequence |
|---|---|---|
| **Gmail SMTP (free account)** | ~500 emails/day cap; needs an App Password (2-Step Verification on). | Fine for a demo. Add a dev fallback (**Ethereal** — fake SMTP that returns a preview URL) so we never need real email during testing, and document Brevo's free tier (300/day) as a production alternative. |
| **BullMQ + Redis** | BullMQ is MIT; Redis self-hosted is free. | Full job-queue pipeline at zero cost. |
| **pdfkit** | MIT, pure-JS PDF generation, no headless browser. | Use it for PDF reports. Avoids Puppeteer's ~300MB Chromium download (keeps us lightweight). |
| **SSE over Express** | Native, no extra dependency for one-way live updates. | Use SSE (not WebSocket) for live scan progress. Must disable proxy buffering and set correct headers. |

### 3.4 Detection reliability findings

- **Time-based SQLi** is the most false-positive-prone check. Mitigation baked into the analyzer: measure a baseline round-trip first, require the delayed response to exceed `baseline + payload_delay × 0.8`, and **confirm with a second request** before flagging. Never flag on a single slow response (network jitter).
- **Soft-404 detection** is mandatory before the Exposed Files scanner trusts a 200. Many apps return `200 OK` for missing pages with a custom "not found" body. We request a guaranteed-random path first, fingerprint that response (status + length + a content hash), and only flag a sensitive path if its response *differs* from the soft-404 fingerprint.
- **XSS reflection** must use a **unique canary token** (e.g. `sf<random>`) wrapped in the payload, and confirm the canary appears **unencoded** in an executable context — not merely present in the body (it could be HTML-encoded and safe).

---

## 4. Architecture Decisions & Rationale

### 4.1 Three deployable services, one repo

```
frontend  (React+Vite)  →  backend (Express API + SSE)  →  Redis (BullMQ) → worker (scan engine)
                                      ↓                                            ↓
                                  MongoDB  ←──────────────────────────────────────┘
```

- **`backend`** owns HTTP: auth, REST, SSE streaming, and *enqueuing* scan jobs. It never runs a scan itself — it stays responsive.
- **`worker`** is a separate process running BullMQ workers. This is where crawling/fuzzing happens. Crashing a scan can't take down the API.
- **`frontend`** is static; in production it's built and served by any static host or the backend itself.

**Why split worker from backend?** A fuzzing run is CPU- and socket-heavy. If it shared the event loop with the API, SSE updates would stutter and the UI would feel broken. Separation is the difference between "smooth" and "janky" — and it's a clean talking point for the viva ("we isolated the workload so the API stays responsive").

### 4.2 One worker process, six logical modules — run concurrently with controlled concurrency

The PRD says "6 modules fire simultaneously." We implement that as **six BullMQ queues** consumed by worker(s), but every outbound HTTP request — across all modules — passes through **one shared rate limiter** (token bucket, default 10 req/s). This is the key insight: "simultaneous modules" must **not** mean "60 requests/second hammering the target." The shared limiter keeps us a scanner, not a DoS tool.

### 4.3 MongoDB document model favors read-time simplicity

Vulnerabilities store a denormalized copy of their CVSS metrics and the proof request/response inline. Reports read one scan + its vulnerabilities and render — no expensive joins. Comparison reads N scans for a target and diffs in memory (scan counts are small). This keeps queries trivial and fast.

### 4.4 Comparison identity — how we know "same vuln across scans"

A vulnerability's identity for diffing is a **stable signature**:
```
signature = sha1(type + ":" + normalizedEndpointPath + ":" + parameter)
```
Query strings and IDs are stripped from the path so `/user/1` and `/user/2` collapse to the same IDOR finding. This signature is what powers FIXED / PERSISTS / NEW / REGRESSED status. (Defined once, tested hard — see Phase 4.)

---

## 5. Definitive Tech Stack (with versions)

Pinned to avoid "works on my machine." Exact patch versions get locked in `package-lock.json` at install.

### Frontend
| Package | Version | Role |
|---|---|---|
| react / react-dom | ^18.3 | UI |
| vite | ^5 | Build + dev server (fast, small output) |
| tailwindcss | ^3.4 | Styling |
| react-router-dom | ^6.26 | Routing (enables route-based code splitting) |
| @tanstack/react-query | ^5 | Server state, polling, cache |
| recharts | ^2.12 | Score trend + severity charts |
| lucide-react | latest | Icons |
| framer-motion | ^11 | Card/score animations (imported per-component, not globally) |
| @tanstack/react-virtual | ^3 | Virtualized long lists (vuln tables, terminal log) |

### Backend & Worker
| Package | Version | Role |
|---|---|---|
| node | 20 LTS | Runtime |
| express | ^4.19 | API + SSE |
| mongoose | ^8 | MongoDB ODM |
| bullmq | ^5 | Job queues |
| ioredis | ^5 | Redis client |
| nodemailer | ^6 | OTP email |
| jsonwebtoken | ^9 | JWT |
| cookie-parser | ^1.4 | Read httpOnly cookie |
| axios | ^1.7 | HTTP to target |
| cheerio | ^1.0 | HTML parsing |
| p-limit | ^5 | In-module concurrency cap |
| helmet | ^7 | Security headers for SmartFuzz itself |
| express-rate-limit | ^7 | API abuse protection |
| zod | ^3 | Request validation |
| pino | ^9 | Structured logging |
| pdfkit | ^0.15 | PDF reports |
| ipaddr.js | ^2 | SSRF guard (private-range detection) |

### Testing
| Package | Version | Role |
|---|---|---|
| vitest | ^2 | Unit/integration tests (both ends) |
| supertest | ^7 | API endpoint tests |
| mongodb-memory-server | ^10 | Ephemeral Mongo for tests (no external DB) |
| nock | ^13 | Mock target HTTP responses deterministically |
| @testing-library/react | ^16 | Component tests |
| playwright | ^1.47 | One end-to-end happy-path test |

### Infra
Docker + Docker Compose. MongoDB 7 and Redis 7 official images. A `testing` compose profile brings up DVWA / WebGoat / NodeGoat / bWAPP as scan targets.

---

## 6. Monorepo Layout

```
smartfuzz/
├── docker-compose.yml
├── docker-compose.testing.yml         # vulnerable targets (profile: testing)
├── .env.example
├── README.md
├── THIRD_PARTY_NOTICES.md             # license attributions (Phase 1)
│
├── frontend/                          # React + Vite + Tailwind
│   └── src/{pages,components,hooks,api,styles,lib}
│
├── backend/                           # Express API + SSE (no scanning here)
│   └── src/{routes,controllers,middleware,models,services,queue,lib}
│
├── worker/                            # BullMQ workers + the scan engine
│   └── src/
│       ├── workers/                   # one per module (thin: pull job → call module)
│       ├── engine/                    # crawler, classifier, payloadEngine, httpSender,
│       │                              #   responseAnalyzer, mutationEngine, authTester,
│       │                              #   techFingerprinter, passiveAnalyzer, exposedFiles
│       ├── scoring/                   # cvss.js (Appendix-A roundup), securityScore.js
│       ├── safety/                    # urlGuard.js (SSRF), rateLimiter.js, consent.js
│       └── knowledge/                 # fixGuides.json, cveDatabase.json,
│                                      #   sensitivePaths.json, zapRules.js, securityHeaders.js
│
├── shared/                            # types/constants reused across services
│   └── src/{vulnTypes.js, cvssVectors.js, signatures.js}
│
├── payloads/                          # cloned at setup (git-ignored), seeded to Mongo
│   ├── seed.js
│   └── (seclists/ patt/ fuzzdb/ — created by setup script)
│
└── docs/
    ├── SmartFuzz_PRD.md
    └── IMPLEMENTATION_PLAN.md         # this file
```

`shared/` exists so the CVSS vectors, vuln-type enum, and signature function are defined **once** and imported by backend, worker, and tests. No copy-paste drift.

---

## 7. Test-Driven Development Strategy

**The rule:** for every module with logic (not glue), the test is written first or in the same commit, and it fails before the implementation exists.

### What gets tested at which level

| Level | Tooling | What it covers | Examples |
|---|---|---|---|
| **Unit** | Vitest | Pure functions, deterministic. The bulk of our tests. | CVSS calc returns 10.0 for the SQLi vector; paramClassifier maps `user_id`→`NUMERIC_ID`; responseAnalyzer flags a MySQL error string; signature() collapses `/user/1` and `/user/2`. |
| **Integration** | Vitest + supertest + mongodb-memory-server + nock | A module or route against a real (in-memory) DB and a **mocked** target. | `POST /api/scans` enqueues a job; the fuzz worker against a nock'd vulnerable endpoint produces one vuln document; OTP verify issues a JWT. |
| **Component** | Testing Library | React components render and respond. | VulnerabilityCard shows severity color; ComparisonTable renders FIXED/NEW badges. |
| **E2E** | Playwright | One full happy path. | Enter email → (OTP stubbed) → start scan against a local mock target → see a vuln appear → open report. |

### Critical testing principle: **the scanner is tested against mocks, never the live internet**

Every detection rule is tested by feeding the `responseAnalyzer` a **canned HTTP response** (via `nock` or a fixture) that we control. This makes tests:
- **Deterministic** — no flaky network.
- **Safe** — we never fuzz a real external site in CI.
- **Fast** — milliseconds, not minutes.

The vulnerable Docker targets (DVWA etc.) are for **manual/metric testing** (Phase 6 detection-rate measurement), not for the automated suite.

### Coverage target
- Engine modules (scoring, classifier, analyzer, signature, urlGuard): **>90%** — these are the correctness-critical core.
- Routes/services: **>75%**.
- Overall gate in CI: **>80%**, build fails below it.

### Test fixtures library
`worker/src/engine/__fixtures__/` holds real-world response samples: a MySQL error page, an Oracle `ORA-` page, an `/etc/passwd` body, a reflected-XSS echo, a clean 404, a soft-404, a CORS-misconfigured header set. Each detection rule has a "should fire" fixture **and** a "should NOT fire" fixture (false-positive guard).

---

## 8. Phase-by-Phase Implementation Plan

Each phase ends with a **green test suite** and a **demoable artifact**. The original PRD's week numbers are kept as a guide; the ordering is what matters.

### Phase 0 — Project Spine (before any feature)
**Goal:** the repo runs, tests run, CI is green on an empty shell.
- [ ] Monorepo init; `package.json` per service; shared workspace.
- [ ] Docker Compose: Mongo + Redis + backend + worker + frontend all start with one command.
- [ ] Vitest configured in all three services; one trivial passing test each.
- [ ] `.env.example`, config loader (zod-validated env), pino logger.
- [ ] `THIRD_PARTY_NOTICES.md` skeleton.
- **Done when:** `docker compose up` boots everything; `npm test` is green everywhere.

### Phase 1 — Foundation: Auth + Seeding (PRD Phase 1)
**Goal:** a user can verify by OTP and the payload library is in Mongo.
- [ ] Mongoose models: User, Target, Scan, Vulnerability, Payload, Report.
- [ ] **OTP flow (TDD):** `send-otp` (generate, hash with bcrypt, store in Redis 10-min TTL, email via Nodemailer; **Ethereal** in dev), `verify-otp` (compare, issue JWT httpOnly cookie), `logout`, `me`.
- [ ] Auth middleware (JWT verify) — tested for valid/expired/missing/tampered token.
- [ ] **Payload seeding:** `setup` script clones the three repos; `payloads/seed.js` parses the relevant wordlist files into the `payloads` collection, tagged by type. Idempotent (re-running doesn't duplicate).
- [ ] React shell: routing, Tailwind hacker theme tokens, the Verify page wired to the OTP API.
- **Done when:** I can run the app, enter an email, get an OTP (preview URL in dev), and land authenticated on an empty dashboard. Payload count in Mongo > 0.
- **Edge cases tested:** expired OTP, wrong OTP (retry allowed), resend throttling, OTP for malformed email rejected, JWT expiry → 401.

### Phase 2 — Passive Modules + Crawler (PRD Phase 2)
**Goal:** point at a target, discover its surface, get passive findings — no payloads sent yet.
- [ ] **SSRF urlGuard first** (Section 10) — nothing makes an outbound request until this exists and is tested.
- [ ] Crawler: axios + cheerio, depth-limited, dedup, scope-locked to the target host, response-size cap, timeout. Outputs `{url, method, params[], contentType}`.
- [ ] Passive Analyzer: security headers, cookie flags, SSL/TLS, CORS, info disclosure, HTTP→HTTPS.
- [ ] Exposed Files Scanner **with soft-404 detection** (Section 3.4).
- [ ] Tech Fingerprinter + local `cveDatabase.json` matching.
- [ ] BullMQ wiring for these modules; SSE endpoint streams progress; Scan Monitor page shows live module status.
- **Done when:** scanning a local DVWA discovers endpoints and reports real passive findings, visible live in the UI.
- **Edge cases tested:** unreachable host, redirect loop, non-HTML content type, huge response (capped), self-signed cert handled gracefully, soft-404 site yields zero false "exposed file" hits.

### Phase 3 — The Fuzzing Engine (PRD Phase 3)
**Goal:** active detection of the injection-class vulnerabilities.
- [ ] Parameter Classifier (rule engine) — fully unit-tested against the PRD's mapping table.
- [ ] Payload Engine — query Mongo by attack type, prioritize, cap count.
- [ ] HTTP Sender — fires through the **shared rate limiter**; captures status/headers/body/timing.
- [ ] Response Analyzer — ZAP-ported rules: SQLi (error/boolean/time, with the time-based double-confirm), XSS (canary technique), path traversal, command injection, SSTI, open redirect. Each rule has fire + no-fire fixtures.
- [ ] Mutation Engine — bypass variants for HIGH_INTEREST-but-unconfirmed responses; second-round fuzz.
- [ ] Auth Tester — lockout check, session-fixation, JWT `alg:none`, cookie flags, default creds.
- **Done when:** full pipeline against DVWA confirms SQLi + XSS with stored proof (request+response). Boolean/time SQLi confirmed without false positives on a clean app.
- **Edge cases tested:** target that blocks after N requests (we back off, don't crash), payload that crashes target → 500 handled, network jitter doesn't trigger false time-based SQLi, mutation round terminates (no infinite loop).

### Phase 4 — Scoring, Reports, Comparison (PRD Phase 4)
**Goal:** findings become scored, reported, and comparable across scans.
- [ ] **CVSS calculator** — `shared` module, Appendix-A roundup, scope-dependent PR. Unit tests assert the three verified vectors (10.0 / 6.1 / 9.3) plus a scope-changed PR case.
- [ ] Overall security score (100 − penalties, floored at 0).
- [ ] **Fix Guidance** — `fixGuides.json` covering all 22 types, 3-layer structure. A test asserts every vuln type the engine can emit has a matching fix guide (100% coverage gate).
- [ ] Report generator: JSON, PDF (pdfkit), CSV, Markdown.
- [ ] **Comparison engine** — signature-based diff → FIXED / PERSISTS / NEW / REGRESSED. Heavily tested (this is the headline feature).
- [ ] Verify-Fix: single-endpoint, single-payload re-test.
- **Done when:** a completed scan produces a full report in all four formats; scanning twice with a fix in between shows the fixed vuln as FIXED in the comparison table.
- **Edge cases tested:** comparison with only one scan (no prior), a regressed vuln (fixed then reappears), a target whose endpoints changed between scans, score never negative.

### Phase 5 — Frontend (PRD Phase 5)
**Goal:** all seven pages, the hacker theme, live updates, and performance.
- [ ] All pages from PRD §18, route-based code splitting (`React.lazy`).
- [ ] SSE hook for the live monitor; React Query for everything else.
- [ ] CVSS breakdown component, comparison table (sticky first column, horizontal scroll on mobile), score-trend chart.
- [ ] Virtualized vuln table + terminal log.
- [ ] Skeleton screens (no spinners); Framer Motion card/score animations.
- [ ] Full responsive pass: bottom-nav on mobile, swipe actions, etc.
- **Done when:** Lighthouse mobile performance is solid; every page works at 320px and at desktop width; lists of 500+ items scroll smoothly.

### Phase 6 — Testing, Metrics & Polish (PRD Phase 6)
**Goal:** the numbers for the report and a clean final build.
- [ ] Run against DVWA / WebGoat / NodeGoat / bWAPP; record detection rate, false-positive rate, OWASP coverage, scan duration (the PRD's metric table).
- [ ] Tune rules to hit >85% detection, <5% false positives.
- [ ] One Playwright E2E happy path in CI.
- [ ] Production Docker build; README with setup + the legal-use disclaimer.
- [ ] Final pass on accessibility basics (focus states, contrast, alt text) and the THIRD_PARTY_NOTICES file.
- **Done when:** the metric table in the PRD is filled with real measured numbers and the whole thing comes up with one command on a fresh machine.

---

## 9. The Scanning Engine — Module Contracts

Each engine module is a pure-ish function with a typed input and output, so it's unit-testable in isolation. Contracts (informal):

```
crawler(targetUrl, config)            → Endpoint[]          // {url, method, params[], contentType}
paramClassifier(param, contentType)   → { category, attackTypes[] }
payloadEngine(category)               → Payload[]           // from Mongo, prioritized, capped
httpSender(request)                   → Response            // {status, headers, body(capped), timeMs}  [via rate limiter]
responseAnalyzer(baseline, response, payloadMeta) → Finding | HighInterest | null
mutationEngine(payload, vulnType)     → Payload[]           // bypass variants
cvss(metrics)                         → { score, vector, severity }
securityScore(vulnCounts)             → number 0..100
signature(type, endpoint, parameter)  → string              // stable identity for diffing
compare(scans[])                      → ComparisonRow[]      // FIXED/PERSISTS/NEW/REGRESSED
```

The **worker files are thin**: pull job → call the module → write result to Mongo → emit SSE progress. All logic lives in `engine/`, which keeps tests free of BullMQ/Redis.

---

## 10. Safety Engineering (Critical)

A vulnerability scanner that can be pointed anywhere is a weapon. These guards are **mandatory** and built before the first outbound request. They are also strong viva material.

### 10.1 SSRF / target guard (`safety/urlGuard.js`)
Before any request to a target, validate the URL:
- Resolve the hostname; **reject** if it maps to a private/reserved range — loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16` incl. the cloud metadata IP `169.254.169.254`), and `0.0.0.0`. Use `ipaddr.js`.
- Reject non-`http(s)` schemes (`file:`, `gopher:`, `ftp:`).
- Re-check on **every redirect hop** (an allowed host can 302 to `localhost`). Cap redirects.
- **Exception for local testing:** a `SCAN_ALLOW_PRIVATE=true` env flag (off by default) lets us scan DVWA on localhost. Off in any shared deployment.
- Unit-tested with a table of malicious URLs that must all be rejected.

### 10.2 Outbound rate limiting (`safety/rateLimiter.js`)
One shared token-bucket across all modules. Default 10 req/s, configurable per scan. Prevents the "6 modules = accidental DoS" failure. Tested: bursts are smoothed to the configured rate.

### 10.3 Authorization consent gate (`safety/consent.js`)
A scan cannot start unless the request carries an explicit `authorized: true` confirmation ("I own this target or have written permission"). Stored on the scan document with the user id and timestamp = an **audit log**. The UI shows the legal warning (IT Act 2000 / CFAA) before the Scan button activates.

### 10.4 Resource caps
- Response body capped (e.g. 2 MB) and truncated before storage (Mongo doc stays small).
- Per-request timeout; per-scan total wall-clock budget.
- Crawler max depth + max-endpoints ceiling so a link-farm can't explode the queue.

### 10.5 SmartFuzz protecting itself
`helmet`, strict CORS (only our frontend origin), `express-rate-limit` on auth routes, zod validation on every body, JWT in httpOnly+SameSite cookie, no secrets in client. We must pass our own scanner — that's a great demo moment.

---

## 11. Edge Cases & How We Handle Each

| Edge case | Handling |
|---|---|
| Target is down / DNS fails | Scan fails gracefully with a clear status; partial findings (if any) saved; UI shows "target unreachable." |
| Target returns soft-404 (200 for missing pages) | Soft-404 fingerprint computed first; exposed-files only flags responses that differ from it. |
| Network jitter mimics time-based SQLi | Baseline timing + 0.8× threshold + second-request confirmation; never flag on one slow response. |
| Reflected payload is HTML-encoded (safe) | Canary must appear **unencoded** in an executable context to confirm XSS; encoded reflection = not vulnerable. |
| Target blocks/rate-limits us mid-scan | Detect 429/connection resets → back off, mark module degraded, continue others; don't crash the scan. |
| Infinite crawl (calendar links, session ids) | Depth cap + endpoint ceiling + URL normalization for dedup. |
| Huge response body (file download) | Size cap + streaming abort; never buffer unbounded into memory. |
| Self-signed / expired TLS cert | Recorded as a **finding**, not a crash; request proceeds with cert errors captured. |
| Redirect to internal host | urlGuard re-checks every hop; internal redirect target is rejected. |
| Two scans where endpoints changed | Comparison keys on signature; missing endpoints show as FIXED, new ones as NEW — never a crash. |
| Vuln type with no fix guide | CI test fails the build (every emittable type must have a guide). |
| OTP email provider down in dev | Ethereal fallback returns a preview URL; tests stub the mailer entirely. |
| Duplicate findings in one scan | Deduped by signature before storage. |
| Security score math underflow | Floored at 0; unit-tested. |
| Concurrent scans by same user | Each is an isolated job set; queues namespaced by scanId. |
| SSE connection drops | Client auto-reconnects; React Query refetch reconciles missed state on reconnect. |

---

## 12. Frontend Performance Plan (Lazy Loading)

"Smooth and lightweight" is a requirement, so it's engineered, not hoped for:

- **Route-based code splitting:** every page is `React.lazy()` + `<Suspense>` with a skeleton fallback. The Verify page loads without pulling the chart/animation libraries.
- **Component-level lazy:** Recharts and the PDF preview load only on the pages that use them (charts are heavy).
- **List virtualization:** `@tanstack/react-virtual` for the vulnerability table and the live terminal log — only visible rows render, so 1,000 findings scroll at 60fps.
- **Framer Motion scoped:** imported per-component, animations kept to transform/opacity (GPU-friendly), respects `prefers-reduced-motion`.
- **Skeletons, not spinners:** every async surface shows a skeleton matching its final shape.
- **Vite build:** small output, tree-shaken, manual chunks for vendor libs.
- **Images/icons:** SVG icons via `lucide-react` (tree-shaken per-icon), no icon-font bloat.
- **Data fetching:** React Query caches and dedupes; the live monitor uses SSE so we're not polling aggressively.

---

## 13. Definition of Done — Per Feature

A feature is "done" only when **all** are true:
1. Unit + integration tests written and green.
2. No-fire (false-positive) test exists for any detection rule.
3. Works against the relevant local vulnerable target (manual check).
4. Error/edge paths handled (from Section 11), not just the happy path.
5. UI piece (if any) is responsive at 320px and desktop, lazy-loaded, with a skeleton state.
6. No secret/credential in client code; inputs validated server-side.
7. Coverage gate still passes.

---

## 14. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Detection rate below 85% target | Medium | High | Port ZAP rules faithfully; add fixtures from real DVWA responses; tune in Phase 6 with measured data. |
| "It's just a wrapper" critique | Low (we chose custom engine) | High | Own engine + THIRD_PARTY_NOTICES showing we only use *data*, not others' code. Clear viva narrative. |
| Gmail SMTP blocked / limited during demo | Medium | Medium | Ethereal in dev; demo can use Ethereal preview or a pre-seeded session; document Brevo fallback. |
| Time-based SQLi false positives | Medium | Medium | Double-confirm + baseline thresholding (Section 3.4). |
| Scope creep (too many vuln types) | Medium | Medium | Phases are ordered by value; injection-class first. A type can ship "detection + score + fix guide" or be cut cleanly. |
| Scanner accidentally hits external infra | Low | High | urlGuard rejects private ranges by default; consent gate; rate limit. |
| Frontend feels heavy | Low | Medium | Lazy loading + virtualization plan (Section 12), measured with Lighthouse. |

---

## 15. What to Demo to the Examiner

A 5-minute story that lands every graded point:
1. **Verify by OTP** — "no passwords stored, ironic-proof for a security tool."
2. **Start a scan on local DVWA**, confirm authorization → watch the **live terminal + module status** fill in via SSE.
3. **Vulnerabilities appear in real time**, each with a **CVSS score and vector** (open one, show the metric breakdown).
4. **Open the fix guide** for SQLi — the 3-layer, multi-language remediation.
5. **Download the PDF report.**
6. **"Now I fix the app"** — switch DVWA to a higher security level (simulating a fix), **Rescan**, and show the **comparison table**: SQLi now **FIXED**, score trend **up**.
7. **Show the safety story** — point the scanner at `localhost`/`169.254.169.254` and show urlGuard **refusing** — then run SmartFuzz against itself and show it's clean.

That arc demonstrates: original engine, real scoring, live UX, the headline rescan-comparison feature, remediation value, and security maturity — exactly what gets a final-year project a top grade.

---

*SmartFuzz Implementation Plan v1.0 — build it phase by phase, test-first, zero cost, no loose ends.*
