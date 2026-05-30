# SmartFuzz — Web Vulnerability Scanner
## Product Requirements Document (PRD)
> Version 3.0 | Final Year Project | Sinhgad College of Engineering, Pune
> Companion build doc: `IMPLEMENTATION_PLAN.md` (phases, TDD, edge cases, safety engineering)

---

## 0. Locked Decisions & Research Corrections (v3.0)

This version resolves the three open questions from v2.0 and folds in facts verified against primary sources during research.

**Locked decisions:**
1. **Scanning engine = custom Node.js.** We build our own crawler, fuzzer, and analyzer. We use the five open-source tools as *data and reference only* — payload wordlists are cloned and seeded into MongoDB, ZAP detection patterns are re-implemented (clean-room) in JS. We do **not** invoke ZAP/Nikto/Nuclei at runtime. Originality is the engineering contribution.
2. **User verification = email OTP, no password** (Section 5). Confirmed as the lightest, free, examiner-friendly choice.
3. **CVSS v3.1** is implemented deliberately (Section 7). **CVSS v4.0 exists** (published 2023-11-01) — the report must acknowledge this and justify v3.1 as the still-dominant standard (NVD, most scanners), **not** call it "the latest."

**Verified facts (primary sources):**
- **Licensing (all free, redistributable):** SecLists = MIT · PayloadsAllTheThings = MIT · FuzzDB = BSD + CC-BY-3.0 + Apache-2.0 + MIT (with attribution) · OWASP ZAP `pscanrules` = Apache-2.0 (we port patterns) · Wapiti = GPL v2 (**study-only**, clean-room re-implementation, never linked/copied). A `THIRD_PARTY_NOTICES.md` will list all attributions.
- **CVSS pre-calc scores are correct:** SQLi `10.0`, Reflected XSS `6.1`, SSRF `9.3` all reproduce from the official formula. Implementation **must** use the integer-arithmetic Roundup (spec Appendix A), and PR is **scope-dependent** (PR:L=0.68 / PR:H=0.5 when Scope=Changed).
- **Gmail free SMTP** ≈ 500 emails/day, needs an App Password (2-Step Verification on). Dev uses **Ethereal** (fake SMTP, preview URLs); Brevo (300/day) is a documented production fallback.
- **BullMQ (MIT) + self-hosted Redis** and **pdfkit (MIT, no headless browser)** keep the whole stack free and lightweight.

**Mandatory safety engineering (see IMPLEMENTATION_PLAN.md §10):** SSRF target guard (reject private/loopback/cloud-metadata ranges, re-check every redirect), shared outbound rate limiter, explicit authorization consent gate + audit log, soft-404 detection before flagging exposed files, and double-confirmation for time-based SQLi to avoid network-jitter false positives.

---

## Table of Contents

1. [Product Vision](#1-product-vision)
2. [The Problem](#2-the-problem)
3. [What We Are Building](#3-what-we-are-building)
4. [User Flow — End to End](#4-user-flow--end-to-end)
5. [User Verification & Session Design](#5-user-verification--session-design)
6. [Attack Coverage — All Types](#6-attack-coverage--all-types)
7. [CVSS Vulnerability Severity Scoring](#7-cvss-vulnerability-severity-scoring)
8. [The Five Open Source Tools — Free & Publicly Accessible](#8-the-five-open-source-tools--free--publicly-accessible)
9. [Backend Scanning Pipeline](#9-backend-scanning-pipeline)
10. [Fix Guidance Engine](#10-fix-guidance-engine)
11. [Rescan & Comparison Engine](#11-rescan--comparison-engine)
12. [Report Generation](#12-report-generation)
13. [System Architecture](#13-system-architecture)
14. [Tech Stack](#14-tech-stack)
15. [Database Design](#15-database-design)
16. [API Design](#16-api-design)
17. [UI/UX Design System](#17-uiux-design-system)
18. [Page-by-Page UI Breakdown](#18-page-by-page-ui-breakdown)
19. [Mobile Responsiveness](#19-mobile-responsiveness)
20. [Testing Strategy](#20-testing-strategy)
21. [Project Folder Structure](#21-project-folder-structure)
22. [Development Phases](#22-development-phases)

---

## 1. Product Vision

SmartFuzz is a zero-cost, fully local, intelligent web vulnerability scanner. A user enters a URL. SmartFuzz does everything else — crawls the target, runs all attack modules simultaneously, scores every vulnerability with an industry-standard CVSS score, generates a detailed fix guide, and produces a structured report.

When the user fixes their website and wants to verify, they rescan and SmartFuzz shows a side-by-side comparison of every scan ever run against that target — what was vulnerable before, what is fixed now, and what is new.

**No AI APIs. No subscriptions. No paid tools. Zero cost. Runs 100% locally.**

---

## 2. The Problem

### Who Is This For

- Final year CS/IT students who built a web project and want to test it before submission
- Junior developers who shipped a web app and want a basic security audit
- College labs that need a free, local, working security scanner
- Anyone who wants to understand their website's vulnerabilities without paying for Burp Suite Pro ($449/year)

### Why Existing Tools Fail

| Tool | Problem |
|---|---|
| Burp Suite Pro | $449/year, steep learning curve |
| OWASP ZAP | Outdated UI, complex config, no fix guidance |
| Nikto | CLI only, no dashboard, no reporting |
| LLM-based fuzzers | Just ChatGPT wrappers — not real scanning |
| sqlmap / wfuzz | Single-purpose, no unified pipeline |

**The gap:** No free tool exists that combines intelligent scanning + severity scoring + fix guidance + scan comparison in a single modern web dashboard.

---

## 3. What We Are Building

A full-stack web application where:

1. User enters a target URL (the only thing they do)
2. Backend runs 6 scanning modules simultaneously
3. All findings are scored with CVSS severity
4. A detailed report is generated with vulnerability details + step-by-step fix guide
5. User can rescan anytime and compare against all previous scans
6. UI is hacker-themed, fast, mobile responsive, and built for impact

---

## 4. User Flow — End to End

```
┌─────────────────────────────────────────────────────────┐
│  User lands on SmartFuzz                                │
│  Enters email → gets OTP → verified (no password)      │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Dashboard                                              │
│  User enters target URL: https://example.com            │
│  Clicks "Start Scan"                                    │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Backend: All 6 modules fire simultaneously             │
│  ├── Crawler discovers all endpoints & params           │
│  ├── Passive Analyzer checks headers, SSL, cookies      │
│  ├── Exposed Files Scanner checks 100+ sensitive paths  │
│  ├── Payload Fuzzer fires SQLi, XSS, RCE, etc payloads  │
│  ├── Auth Tester checks brute force, session security   │
│  └── Tech Fingerprinter detects stack & known CVEs      │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Live Dashboard Updates (real-time via SSE)             │
│  User watches vulnerabilities appear as found           │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Scan Complete → Full Report Generated                  │
│  ├── All vulnerabilities listed with CVSS score         │
│  ├── Each vuln has full request/response proof          │
│  ├── Step-by-step fix guide per vulnerability           │
│  └── Overall security score for the website            │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  User fixes their website                               │
│  Clicks "Rescan" on same target                         │
│  SmartFuzz scans again                                  │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Comparison View                                        │
│  Shows Scan 1 vs Scan 2 vs Scan 3 (as many as run)     │
│  ├── ✅ XSS — Fixed (was in Scan 1, gone in Scan 2)    │
│  ├── ✅ SQLi — Fixed                                   │
│  ├── 🔴 IDOR — Still Vulnerable                        │
│  └── 🆕 Open Redirect — Newly Discovered               │
└─────────────────────────────────────────────────────────┘
```

---

## 5. User Verification & Session Design

### Decision: OTP-Based Verification (No Password)

There is no traditional username/password login. The user verifies via email OTP only. This is simpler, more secure, and removes the need to store passwords entirely.

### Why OTP (Not Password Login)

- SmartFuzz is a security tool — ironic to have weak password auth
- Removes password storage, hashing, reset flows entirely
- Users don't need to "create an account" — just verify email and go
- One less thing to build and maintain

### Verification Flow

```
User enters email address
      ↓
Backend generates 6-digit OTP
Stores in Redis with 10-minute expiry: OTP:user@email.com → 482910
Sends OTP to email (using Nodemailer + Gmail SMTP — free)
      ↓
User enters OTP on screen
      ↓
Backend verifies OTP against Redis
If match → creates/finds user in MongoDB
         → issues JWT token (expires 7 days)
         → stores in httpOnly cookie
If no match → error, allow retry
      ↓
User is now verified — JWT cookie sent with every request
Express middleware validates JWT on all protected routes
      ↓
User logs out → JWT cookie cleared
```

### What Is Stored Per User

```
- email (identifier)
- all scans they have ever run
- scan history per target URL
- nothing else
```

### Free Email Sending

Use **Nodemailer + Gmail SMTP** — completely free, no third-party email service needed.

```
Gmail account → App Password (2-Step Verification ON) → Nodemailer config → OTP email sent
```

Zero cost. Free Gmail caps at ~500 emails/day — ample for this project.

**Development & fallback:**
- **Dev:** use **Ethereal** (Nodemailer's free fake-SMTP) — it captures the OTP email and returns a preview URL, so no real inbox or App Password is needed while building/testing.
- **Production fallback (if Gmail is blocked during a demo):** Brevo's free tier (≈300 emails/day). Documented but not required.

---

## 6. Attack Coverage — All Types

SmartFuzz covers every major web vulnerability category. Organized by OWASP Top 10 (2021).

### A01 — Broken Access Control

| Attack | How Detected |
|---|---|
| IDOR (Insecure Direct Object Reference) | Enumerate numeric IDs in endpoints, check if unauthorized data is returned |
| Privilege Escalation | Access admin-only endpoints without auth headers |
| Directory Listing | Check if /uploads/, /files/, /backup/ return directory contents |
| Forced Browsing | Request hidden paths not linked from UI |

### A02 — Cryptographic Failures

| Attack | How Detected |
|---|---|
| Sensitive Data in Response | Regex scan response bodies for passwords, API keys, tokens, credit card patterns |
| HTTP (no HTTPS) | Check if site is accessible over plain HTTP |
| Weak SSL/TLS | Check TLS version, expired cert, self-signed cert using Node tls module |
| Passwords in URL | Check if auth tokens/passwords appear in GET parameters |

### A03 — Injection

| Attack | How Detected |
|---|---|
| SQL Injection (Error-based) | Error messages containing SQL keywords in response |
| SQL Injection (Boolean-based) | Different response content for true vs false conditions |
| SQL Injection (Time-based) | Response time > 5s when payload contains SLEEP/WAITFOR |
| NoSQL Injection (MongoDB) | Inject `{"$gt": ""}` type payloads in JSON body parameters |
| XSS — Reflected | Payload appears unescaped in response body |
| XSS — Stored | Payload stored and returned in subsequent GET request |
| Command Injection | Response contains OS command output (uid=, etc.) |
| LDAP Injection | Inject LDAP metacharacters in auth fields |
| XML Injection | Inject XML metacharacters in XML-accepting endpoints |
| Template Injection (SSTI) | Inject `{{7*7}}` — if `49` in response, vulnerable |
| HTTP Header Injection | Inject CRLF sequences in header-reflected parameters |

### A04 — Insecure Design

| Attack | How Detected |
|---|---|
| CSRF | Check if state-changing forms have CSRF tokens |
| Mass Assignment | Send extra unexpected parameters in POST body, check if accepted |
| Business Logic Flaws | Negative quantity, zero price, skipping steps in multi-step flows |

### A05 — Security Misconfiguration

| Attack | How Detected |
|---|---|
| Missing Security Headers | Check all 8 critical security response headers |
| CORS Misconfiguration | Check Access-Control-Allow-Origin: * on sensitive endpoints |
| Default Credentials | Try admin/admin, admin/password on detected admin panels |
| Verbose Error Messages | Check if stack traces or server info appear in error responses |
| Exposed Admin Panels | Check /admin, /administrator, /wp-admin, /phpmyadmin, /dashboard |

### A06 — Vulnerable & Outdated Components

| Attack | How Detected |
|---|---|
| Version Disclosure | Read Server, X-Powered-By headers for version numbers |
| Known CVE Matching | Match detected versions against local CVE list for that technology |
| Outdated Libraries | Detect JS library versions from HTML source (jQuery, Bootstrap) |

### A07 — Auth & Session Failures

| Attack | How Detected |
|---|---|
| Brute Force (No Lockout) | Send 20 login requests with wrong passwords, check if blocked |
| Weak Session Tokens | Analyze session cookie entropy and predictability |
| Session Fixation | Check if session ID changes after login |
| JWT Algorithm: None | Send JWT with alg:none header, check if accepted |
| Missing HttpOnly/Secure Flags | Inspect all Set-Cookie response headers |
| Session Not Invalidated | Check if old session token works after logout |

### A08 — Software & Data Integrity Failures

| Attack | How Detected |
|---|---|
| Insecure Deserialization | Inject malformed serialized objects in cookies/params |
| Subresource Integrity Missing | Check if external script/CSS tags have integrity attribute |

### A09 — Security Logging Failures (Passive)

| Attack | How Detected |
|---|---|
| No Rate Limiting | Send burst of 50 requests, check if any throttling happens |
| Error Information Leakage | Detailed error pages expose internal paths, line numbers, DB schema |

### A10 — SSRF (Server-Side Request Forgery)

| Attack | How Detected |
|---|---|
| Basic SSRF | Inject internal URLs (http://localhost, http://127.0.0.1, http://169.254.169.254) in URL-accepting parameters |
| Blind SSRF | Use a free webhook listener (webhook.site) to detect out-of-band callbacks |

### Additional Checks (Beyond OWASP Top 10)

| Attack | How Detected |
|---|---|
| Clickjacking | Check X-Frame-Options and CSP frame-ancestors |
| Open Redirect | Inject external URLs in redirect parameters, check Location header |
| Path Traversal / LFI | Inject ../../etc/passwd patterns in file parameters |
| Remote File Inclusion | Inject remote URL in file parameter |
| Exposed Sensitive Files | Check 100+ known sensitive file paths |
| Cookie Security | HttpOnly, Secure, SameSite flag analysis |
| XXE (XML External Entity) | Inject external entity in XML-accepting endpoints |

---

## 7. CVSS Vulnerability Severity Scoring

Every vulnerability found by SmartFuzz is scored using **CVSS v3.1** — the industry-standard scoring system used by every real security company, CVE database, and penetration testing firm. This is implemented in pure JavaScript — no external API.

> **Implementation correctness (verified against the FIRST.org spec — do not skip):**
> - **Roundup** must use the integer-arithmetic algorithm from spec Appendix A, **not** `Math.ceil(x*10)/10`. Naive rounding is off by 0.1 on float edge cases and would fail a spot-check against NVD scores.
> - **Privileges Required is scope-dependent:** when Scope = Changed, use PR:L = 0.68 and PR:H = 0.5 (instead of 0.62 / 0.27). Implementing PR as a constant under-scores every scope-changed vector.
> - Scope-Changed Impact uses exponent **15** in the base equation (the value 13 belongs only to the Environmental/Modified variant).
> - **CVSS v4.0** is the current published standard (2023-11-01). We implement v3.1 because it remains dominant on NVD and in scanners and has simpler, well-documented base equations — state this in the report rather than calling v3.1 "the latest."

### CVSS Score Ranges

| Score | Severity | Color | Meaning |
|---|---|---|---|
| 9.0 – 10.0 | Critical | 🔴 Red | Immediate action required. Easily exploitable, full impact. |
| 7.0 – 8.9 | High | 🟠 Orange | Serious risk. Fix before going to production. |
| 4.0 – 6.9 | Medium | 🟡 Yellow | Moderate risk. Fix in next development cycle. |
| 0.1 – 3.9 | Low | 🔵 Blue | Minor risk. Fix when convenient. |
| 0.0 | None | ⚪ Grey | Informational only. No direct exploitability. |

### CVSS Metrics Explained (How Score Is Calculated)

CVSS score is calculated from 8 metrics across 3 groups:

#### Base Score Metrics

**Attack Vector (AV)** — How is the vulnerability exploited?
- Network (N) → Exploitable remotely over internet → highest risk
- Adjacent (A) → Exploitable from local network only
- Local (L) → Attacker needs local access
- Physical (P) → Attacker needs physical device access → lowest risk

**Attack Complexity (AC)** — How hard is it to exploit?
- Low (L) → No special conditions, exploit works every time
- High (H) → Requires specific configuration or race condition

**Privileges Required (PR)** — What access does attacker need beforehand?
- None (N) → No login required → highest risk
- Low (L) → Regular user account needed
- High (H) → Admin account needed

**User Interaction (UI)** — Does a victim need to do something?
- None (N) → Fully automated exploit
- Required (R) → Victim must click a link or open a file

**Scope (S)** — Does the vulnerability affect other systems beyond the target?
- Unchanged (U) → Only affects the vulnerable component
- Changed (C) → Can affect other components/systems

**Confidentiality Impact (C)** — Data exposure
- High (H) → Complete data disclosure
- Low (L) → Some data exposed
- None (N) → No data exposed

**Integrity Impact (I)** — Data modification
- High (H) → Complete data modification possible
- Low (L) → Some data can be modified
- None (N) → No data modification

**Availability Impact (A)** — Service disruption
- High (H) → Complete service shutdown possible
- Low (L) → Reduced performance
- None (N) → No availability impact

### Pre-Calculated CVSS Scores Per Vulnerability Type

SmartFuzz uses these pre-calculated base scores for each vulnerability type:

| Vulnerability | AV | AC | PR | UI | S | C | I | A | CVSS Score | Severity |
|---|---|---|---|---|---|---|---|---|---|---|
| SQL Injection (Error-based) | N | L | N | N | C | H | H | H | **10.0** | Critical |
| SQL Injection (Time-based) | N | L | N | N | U | H | H | N | **9.1** | Critical |
| Remote Code Execution | N | L | N | N | C | H | H | H | **10.0** | Critical |
| Command Injection | N | L | N | N | C | H | H | H | **10.0** | Critical |
| SSRF | N | L | N | N | C | H | L | N | **9.3** | Critical |
| XXE | N | L | N | N | U | H | H | N | **9.1** | Critical |
| Stored XSS | N | L | N | R | C | H | H | N | **9.0** | Critical |
| IDOR | N | L | L | N | U | H | H | N | **8.1** | High |
| Reflected XSS | N | L | N | R | C | L | L | N | **6.1** | Medium |
| Path Traversal | N | L | N | N | U | H | N | N | **7.5** | High |
| Open Redirect | N | L | N | R | U | L | L | N | **5.4** | Medium |
| CSRF | N | L | N | R | U | N | H | N | **6.5** | Medium |
| Broken Auth (No Lockout) | N | L | N | N | U | L | L | N | **6.5** | Medium |
| Missing Security Headers | N | L | N | N | U | L | N | N | **5.3** | Medium |
| CORS Misconfiguration | N | L | N | N | U | H | N | N | **7.5** | High |
| JWT alg:none | N | L | N | N | U | H | H | N | **9.1** | Critical |
| Sensitive Data Exposure | N | L | N | N | U | H | N | N | **7.5** | High |
| Exposed Sensitive Files | N | L | N | N | U | H | N | N | **7.5** | High |
| SSL/TLS Weak Config | N | H | N | N | U | H | N | N | **5.9** | Medium |
| Insecure Cookie Flags | N | L | N | N | U | L | N | N | **4.3** | Medium |
| Clickjacking | N | L | N | R | U | N | L | N | **4.3** | Medium |
| Version Disclosure | N | L | N | N | U | L | N | N | **5.3** | Medium |
| SSTI (Template Injection) | N | L | N | N | C | H | H | H | **10.0** | Critical |
| NoSQL Injection | N | L | N | N | U | H | H | N | **9.1** | Critical |
| Directory Listing | N | L | N | N | U | L | N | N | **5.3** | Medium |

### How CVSS Score Is Shown In UI

Every vulnerability card in SmartFuzz shows:

```
┌─────────────────────────────────────────────────┐
│ 🔴 SQL Injection — Error Based          [10.0]  │
│ ████████████████████████████████████ Critical   │
│                                                 │
│ Endpoint:  POST /api/login                      │
│ Parameter: username                             │
│                                                 │
│ CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H │
│                                                 │
│ Attack Vector    ●●●●  Network                  │
│ Attack Complexity ●○○○ Low                      │
│ Privileges Needed ●○○○ None                     │
│ User Interaction  ●○○○ None                     │
│ Confidentiality   ●●●● High                     │
│ Integrity         ●●●● High                     │
│ Availability      ●●●● High                     │
└─────────────────────────────────────────────────┘
```

### Overall Website Security Score

After all vulnerabilities are found, SmartFuzz calculates one overall score for the target website:

```
Overall Security Score = 100 − penalty

Penalty per vulnerability:
  Critical  → −25 points
  High      → −15 points
  Medium    → −8 points
  Low       → −3 points

Minimum score = 0 (cannot go below 0)

Score bands:
  90–100  → 🟢 Secure
  70–89   → 🟡 Needs Attention
  40–69   → 🟠 Vulnerable
  0–39    → 🔴 Critical Risk
```

---

## 8. The Five Open Source Tools — Free & Publicly Accessible

All five tools below are:
- Hosted on GitHub (100% free, public, no account needed)
- Licensed under open licenses (MIT, Apache 2.0, Creative Commons)
- Can be cloned, used, and redistributed in academic projects
- No API key, no subscription, no rate limit

**They are not called as APIs at runtime.** Their payload files (text files full of attack strings) are cloned once from GitHub and loaded into the SmartFuzz MongoDB database at project setup. From that point, SmartFuzz works 100% offline.

---

### Tool 1: SecLists
- **GitHub:** `github.com/danielmiessler/SecLists`
- **License:** MIT
- **Size:** ~1GB of payload wordlists
- **What we use:** `/Fuzzing/SQLi/`, `/Fuzzing/XSS/`, `/Fuzzing/LFI/`, `/Discovery/Web-Content/` directories
- **How it helps:** The largest collection of real-world attack payloads in existence. Used by professional penetration testers worldwide.
- **Role in SmartFuzz:** Primary payload source loaded into MongoDB at setup. The Payload Engine queries this for the right attack type.

---

### Tool 2: PayloadsAllTheThings
- **GitHub:** `github.com/swisskyrepo/PayloadsAllTheThings`
- **License:** MIT
- **What we use:** Filter bypass techniques, WAF evasion payloads, encoding variants per vulnerability type
- **How it helps:** Not just payloads — it explains bypass techniques for every filter developers might add. When a basic payload gets blocked, this is where the mutation engine gets its variants.
- **Role in SmartFuzz:** Feeds the Mutation Engine. When baseline payloads show interest but no confirmation, mutation variants from this repo are tried.

---

### Tool 3: FuzzDB
- **GitHub:** `github.com/fuzzdb-project/fuzzdb`
- **License:** Creative Commons + Open Source
- **What we use:** Attack patterns organized by input type — `/attack/sql-injection/`, `/attack/xss/`, `/attack/rce/`, `/attack/path-traversal/`
- **How it helps:** Unlike SecLists which is broad, FuzzDB is surgical — organized by the type of data being input. Perfect for the Parameter Classifier mapping.
- **Role in SmartFuzz:** Precision payload selection. Once the Parameter Classifier labels a param as `FILE_PATH` type, FuzzDB gives exactly the right payloads for that.

---

### Tool 4: Wapiti
- **GitHub:** `github.com/wapiti-scanner/wapiti`
- **License:** GPL v2 — **study-only.** We read its source for architectural ideas and re-implement equivalent logic in Node.js from scratch (clean-room). We never copy, import, or link its code, so GPL obligations do **not** reach the SmartFuzz codebase. It is cited as a reference, not shipped as a dependency.
- **What we use:** Source code study — specifically its crawler logic, form detection, and response analysis modules
- **How it helps:** Wapiti is a production-grade Python vulnerability scanner. Its source code is the best reference for how a real crawler handles edge cases — JavaScript-rendered forms, multi-step forms, encoded parameters.
- **Role in SmartFuzz:** Architectural blueprint for our Crawler and Response Analyzer. We read the code and implement equivalent logic in Node.js.

---

### Tool 5: OWASP ZAP Passive Scan Rules
- **GitHub:** `github.com/zaproxy/zap-extensions` (under `/addOns/pscanrules/`)
- **License:** Apache 2.0
- **What we use:** The passive scanner rule set — regex patterns and heuristics that detect vulnerabilities from HTTP response content
- **How it helps:** These rules have been built and refined by the OWASP security community for over a decade. They detect SQL error messages, XSS reflection, information leakage, header issues — all the things our Response Analyzer needs to identify.
- **Role in SmartFuzz:** Ported to JavaScript and used as the detection logic in our Response Analyzer. We do not import the Java library — we extract the regex patterns and implement them in Node.js.

---

### Setup: How Tools Are Loaded Into SmartFuzz

```bash
# One-time setup script (runs inside Docker on first launch)
git clone https://github.com/danielmiessler/SecLists ./payloads/seclists
git clone https://github.com/swisskyrepo/PayloadsAllTheThings ./payloads/patt
git clone https://github.com/fuzzdb-project/fuzzdb ./payloads/fuzzdb

# Seed script parses all text files and loads into MongoDB
node scripts/seed-payloads.js

# After this, SmartFuzz works 100% offline
```

---

## 9. Backend Scanning Pipeline

When a user submits a URL, six scanning modules launch simultaneously using BullMQ parallel workers. Each module runs independently and writes findings to MongoDB as it discovers them.

```
User submits: https://target.com
                    │
        ┌───────────▼───────────┐
        │    Scan Orchestrator  │
        │   Creates scan doc    │
        │   in MongoDB          │
        └───────────┬───────────┘
                    │
    ┌───────────────┼───────────────┐
    │ BullMQ fires 6 workers simultaneously │
    │                                       │
    ▼           ▼           ▼           ▼           ▼           ▼
[Module 1]  [Module 2]  [Module 3]  [Module 4]  [Module 5]  [Module 6]
 Crawler    Passive     Exposed     Payload     Auth        Tech
            Analyzer    Files       Fuzzer      Tester      Fingerprint
```

### Module 1: Crawler

Discovers every attack surface of the target website.

**Actions:**
- Fetch root URL with axios
- Parse HTML with cheerio: find all `<form>`, `<input>`, `<a href>`, `<script src>`
- Extract all query parameters from URLs
- Identify POST endpoints from form action attributes
- Recursively crawl all internal links up to depth 3
- Detect API endpoints from JavaScript source files (regex for fetch/axios calls)
- Deduplicate all discovered endpoints

**Output:** List of `{url, method, params[], contentType}` objects stored in MongoDB

---

### Module 2: Passive Analyzer

Checks security issues without sending any malicious payloads. Pure observation.

**Checks:**
- Security headers present/missing (8 critical headers)
- Cookie flags (HttpOnly, Secure, SameSite)
- SSL/TLS certificate validity and version
- CORS header configuration
- Information disclosure in headers (Server version, X-Powered-By)
- Redirects from HTTP to HTTPS
- Content-Type header correctness
- Cache-Control on sensitive endpoints

**Output:** List of passive findings with severity scores

---

### Module 3: Exposed Files Scanner

Fires GET requests at 150+ known sensitive file paths.

**Checks (sample of 150+ paths):**
```
/.env                 /.env.local           /.env.production
/.git/config          /.git/HEAD            /.gitignore
/backup.zip           /backup.tar.gz        /backup.sql
/phpinfo.php          /info.php             /test.php
/admin                /administrator        /wp-admin
/phpmyadmin           /adminer.php          /manager
/api-docs             /swagger.json         /openapi.json
/config.json          /config.yml           /settings.py
/.htpasswd            /.htaccess            /web.config
/server-status        /server-info          /status
/debug                /trace                /actuator
/robots.txt           /sitemap.xml          /.well-known/
/uploads/             /files/               /static/
```

**Logic:** If status code is 200 or 403 (exists but forbidden) → flag it

**Output:** List of accessible sensitive paths with severity

---

### Module 4: Payload Fuzzer

The core fuzzing engine. Fires attack payloads at every discovered parameter.

**Pipeline per endpoint:**
1. Receive endpoint from Crawler output
2. Parameter Classifier labels each param with attack type
3. Payload Engine loads matching payloads from MongoDB (sourced from SecLists/FuzzDB)
4. HTTP Sender fires payloads concurrently (10 req/sec rate limit)
5. Response Analyzer scores each response
6. High-interest responses → Mutation Engine generates bypass variants
7. Second-round fuzzing with mutated payloads
8. Confirmed findings → stored in MongoDB with proof (request + response)

**Parameter Classifier Rules:**

```
param contains [id, uid, user_id, product_id, item_id, order_id]
  → NUMERIC_ID → SQLi, IDOR

param contains [search, q, query, keyword, find, term, s]
  → SEARCH → XSS, SQLi

param contains [file, path, dir, folder, template, page, include, load]
  → FILE_PATH → Path Traversal, LFI, RFI

param contains [redirect, url, next, return, goto, continue, target, link]
  → URL_FIELD → Open Redirect, SSRF

param contains [email, mail]
  → EMAIL → Header Injection, XSS

param contains [cmd, exec, command, run, ping, host, ip]
  → COMMAND → RCE, Command Injection

param contains [user, username, login, pass, password, auth, token]
  → AUTH → Auth Bypass, SQLi, Brute Force

param contains [xml, soap, data] + Content-Type: application/xml
  → XML → XXE

param contains [template, render, view] in Node/Python/PHP apps
  → TEMPLATE → SSTI

input type = hidden
  → HIDDEN → CSRF, Parameter Tampering

default
  → GENERIC → XSS, SQLi (basic set)
```

**Response Analyzer Detection Rules (from ZAP):**

```
SQLi Error-based:
  body contains: "you have an error in your sql syntax"
  body contains: "warning: mysql_"
  body contains: "unclosed quotation mark"
  body contains: "quoted string not properly terminated"
  body contains: "sqliteexception" / "sqlite error"
  body contains: "ORA-" (Oracle)
  body contains: "pg_query" / "psql error" (PostgreSQL)
  → CONFIRMED: SQLi (Error-based)

SQLi Time-based:
  response_time > 5000ms AND payload contained SLEEP/WAITFOR/BENCHMARK
  → CONFIRMED: SQLi (Time-based)

SQLi Boolean-based:
  true_response.body != false_response.body AND
  true_response.body == original_response.body
  → CONFIRMED: SQLi (Boolean-based)

XSS Reflected:
  payload_string appears verbatim in response body unencoded
  → CONFIRMED: XSS (Reflected)

XSS Stored:
  payload stored, subsequent GET to same page contains payload unencoded
  → CONFIRMED: XSS (Stored)

Path Traversal:
  body contains "root:x:0:0" OR "daemon:x:" → Linux /etc/passwd
  body contains "[boot loader]" → Windows win.ini
  → CONFIRMED: Path Traversal

RCE / Command Injection:
  body contains "uid=" AND "gid=" (Linux id command output)
  body contains OS version strings after command payload
  → CONFIRMED: RCE

SSRF:
  internal URL injected → response differs from baseline
  → CONFIRMED: SSRF (Basic)

SSTI:
  {{7*7}} payload → response contains "49"
  ${7*7} payload → response contains "49"
  → CONFIRMED: SSTI

Open Redirect:
  Location header contains injected external domain after redirect payload
  → CONFIRMED: Open Redirect

Anomaly Detection (for deeper investigation):
  status_code == 500 → HIGH INTEREST
  response_size differs from baseline > 20% → MEDIUM INTEREST
  response_time > 3x baseline average → MEDIUM INTEREST
  new error keywords in response → HIGH INTEREST
```

---

### Module 5: Auth Tester

Tests authentication and session security specifically.

**Checks:**
- Send 20 consecutive failed login attempts → check if account is locked or rate limited
- Analyze session cookie entropy (low entropy = predictable = session hijack risk)
- Check if session ID changes after successful login (session fixation)
- If JWT is found: decode header, check if alg:none is accepted
- Check if logout actually invalidates the session token
- Try default credentials on detected admin panels (admin/admin, admin/password, root/root)

---

### Module 6: Tech Fingerprinter

Identifies the technology stack and matches against known vulnerable versions.

**Detection Methods:**
- Read `Server` header → Apache 2.2.x, nginx 1.14, etc.
- Read `X-Powered-By` header → PHP/7.2.0, Express, ASP.NET
- Check HTML source for meta generator tags → WordPress 5.4
- Check for framework-specific paths → /wp-login.php, /laravel, /rails
- Detect JS library versions from HTML → jQuery 1.11.0, Bootstrap 3.0
- Read `X-AspNet-Version`, `X-Runtime` headers

**CVE Matching:**
- Local JSON file: `{technology: "jQuery", version: "< 3.5.0", cve: "CVE-2020-11022", severity: "Medium", description: "XSS via passing HTML from untrusted sources"}`
- Match detected versions against this local CVE database
- Flag any matches as informational/medium findings

---

## 10. Fix Guidance Engine

Every confirmed vulnerability in SmartFuzz comes with a 3-layer fix guide. This is stored as a local knowledge base (JSON file), requires no AI, and covers every vulnerability type SmartFuzz can detect.

### 3-Layer Fix Structure

**Layer 1 — What Is This?**
Plain-language explanation of the vulnerability. What an attacker can do with it. Real-world impact.

**Layer 2 — Step-by-Step Fix**
The actual vulnerable code pattern shown, then the fixed pattern shown, in multiple languages relevant to web development (Node.js, PHP, Python, Java).

**Layer 3 — Verify The Fix**
Exactly what to test after applying the fix. Specific inputs to try. How to confirm the vulnerability is gone. Points to running a SmartFuzz rescan on just that endpoint.

### Example Fix Guide: SQL Injection

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 CRITICAL — SQL Injection (Error-based)
CVSS Score: 10.0 | Endpoint: POST /api/login
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IS THIS?
  Your application builds database queries by directly
  inserting user input into the SQL string. An attacker
  can manipulate the query to: dump your entire database,
  log in as any user without a password, delete all data,
  or in some cases execute OS commands on your server.

REAL WORLD IMPACT
  This vulnerability alone has caused data breaches at
  major companies leaking millions of user records.
  Automated tools can exploit this in seconds.

──── STEP 1: Find The Vulnerable Code ─────────────────

  Look for string concatenation with user input in queries:

  // ❌ VULNERABLE — Node.js + MySQL
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  connection.query(query);

  // ❌ VULNERABLE — PHP
  $query = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";
  mysqli_query($conn, $query);

  // ❌ VULNERABLE — Python
  cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")

──── STEP 2: Fix It ────────────────────────────────────

  Replace with parameterized queries / prepared statements:

  // ✅ FIXED — Node.js + MySQL
  const query = "SELECT * FROM users WHERE email = ?";
  connection.query(query, [email]);

  // ✅ FIXED — Node.js + PostgreSQL
  const query = "SELECT * FROM users WHERE email = $1";
  client.query(query, [email]);

  // ✅ FIXED — PHP + PDO
  $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
  $stmt->execute([$_POST['email']]);

  // ✅ FIXED — Python
  cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

  // ✅ BEST — Use an ORM (no raw SQL at all)
  // Mongoose (Node.js + MongoDB)
  User.findOne({ email: email })
  // Sequelize (Node.js + SQL)
  User.findOne({ where: { email: email } })

──── STEP 3: Additional Hardening ─────────────────────

  Even with parameterized queries, also do these:
  • Add input validation — reject email values that
    contain SQL characters if they shouldn't
  • Use least-privilege DB user — app DB account should
    not have DROP, CREATE, or ALTER permissions
  • Enable WAF rules for SQL keywords in inputs

──── STEP 4: Verify The Fix ────────────────────────────

  After fixing, manually test these inputs in the
  affected field:
    ' OR '1'='1
    ' OR 1=1 --
    1; DROP TABLE users --
    1 UNION SELECT null,null --

  None of these should return data or cause errors.
  Then click "Verify Fix" in SmartFuzz to rescan
  only this endpoint automatically.

──── REFERENCE ─────────────────────────────────────────
  CWE-89 | OWASP A03:2021 | CVSS: AV:N/AC:L/PR:N/UI:N
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Fix Guide Coverage (All Vulnerability Types)

| Vulnerability | Fix Approach Covered |
|---|---|
| SQL Injection | Parameterized queries in 4 languages + ORM examples |
| NoSQL Injection | Schema validation, type checking, mongoose sanitize |
| XSS (Reflected/Stored) | Output encoding, DOMPurify, Content-Security-Policy setup |
| Command Injection | Input allowlisting, avoid exec/system, sandboxing |
| Path Traversal | path.resolve() + base directory validation |
| SSTI | Avoid user-controlled template strings, sandboxed template engines |
| XXE | Disable external entities in XML parser config |
| SSRF | URL allowlist, block internal IPs, disable redirects |
| IDOR | Object-level authorization checks per request |
| CSRF | Token implementation, SameSite cookie, double-submit cookie |
| Open Redirect | Allowlist of valid redirect destinations |
| Broken Auth | Rate limiting, account lockout, bcrypt passwords |
| JWT Issues | Validate alg header, use RS256, verify signature |
| Insecure Cookies | HttpOnly + Secure + SameSite=Strict flags |
| Missing Security Headers | Exact header values to add with explanation |
| CORS Misconfiguration | Explicit allowlist, not wildcard |
| Sensitive Data Exposure | What to scrub, encryption at rest guidance |
| SSL/TLS Issues | Minimum TLS 1.2, disable weak ciphers |
| Exposed Files | .gitignore patterns, server config to block paths |
| Directory Listing | nginx/Apache config to disable autoindex |
| Clickjacking | X-Frame-Options: DENY + CSP frame-ancestors |
| Version Disclosure | Remove version headers from server config |

---

## 11. Rescan & Comparison Engine

This is one of SmartFuzz's most valuable features. A user can rescan the same target as many times as they want — after each fix, after deployments, after updates. SmartFuzz keeps full history and shows a comparison across all scans.

### How Rescan Works

```
Every scan on the same domain is linked by domain/URL in MongoDB.
Scan 1 → Scan 2 → Scan 3 → ... → Scan N
All linked under one Target document.
```

When a user clicks "Rescan":
1. New scan document created, linked to same target
2. Full pipeline runs again (all 6 modules)
3. On completion, comparison is automatically generated
4. User can view any scan or any combination of scans side by side

### Comparison Algorithm

For each vulnerability found across all scans, SmartFuzz assigns a status:

```
FIXED      → Found in Scan X, not found in any later scan
PERSISTS   → Found in Scan X AND in the latest scan
NEW        → Found in latest scan, not in any previous scan
REGRESSED  → Was fixed (missing from Scan Y), reappeared in Scan Z
```

### Comparison View Example

```
Target: https://myapp.com
────────────────────────────────────────────────────────────
Vulnerability          Scan 1    Scan 2    Scan 3    Status
                       Nov 10    Nov 17    Nov 24
────────────────────────────────────────────────────────────
SQLi /api/login        🔴 10.0   ✅ Fixed  ✅ Fixed  ✅ FIXED
XSS /search            🟠 6.1    🟠 6.1    ✅ Fixed  ✅ FIXED
Path Traversal /file   🔴 7.5    🔴 7.5    🔴 7.5    🔴 PERSISTS
IDOR /user/{id}        🟠 8.1    🟠 8.1    🟠 8.1    🔴 PERSISTS
Missing CSP Header     🟡 5.3    ✅ Fixed  ✅ Fixed  ✅ FIXED
Open Redirect          —         🆕 5.4    🆕 5.4    🆕 NEW
Exposed /.env          —         —         🔴 7.5    🆕 NEW
────────────────────────────────────────────────────────────
Security Score         23/100    45/100    52/100    📈 +29
────────────────────────────────────────────────────────────
```

### Security Score Trend Chart

A line graph showing security score across all scans over time. Visual proof of security improvement. Impressive for project demonstration.

### Verify Fix Feature

On any individual vulnerability, a "Verify Fix" button:
- Rescans only that specific endpoint with the exact payload that found the vulnerability
- Takes 5–10 seconds instead of a full scan
- Returns: "✅ Fixed — payload no longer triggers vulnerability" or "❌ Still Vulnerable — same response detected"

---

## 12. Report Generation

Every completed scan generates a full report automatically.

### Report Contents

```
SmartFuzz Security Report
Target: https://myapp.com
Scan Date: 2024-11-10 14:32
Duration: 8 minutes 22 seconds
Scanned By: user@email.com

━━━ EXECUTIVE SUMMARY ━━━━━━━━━━━━━━━━
Overall Security Score: 23/100 — 🔴 Critical Risk
Total Endpoints Scanned: 47
Total Payloads Sent: 12,847
Vulnerabilities Found: 9
  Critical: 3
  High: 2
  Medium: 3
  Low: 1

━━━ VULNERABILITY BREAKDOWN ━━━━━━━━━━
[Full CVSS table of all findings]

━━━ DETAILED FINDINGS ━━━━━━━━━━━━━━━━
[For each vulnerability:]
  - Title, CVSS score, severity
  - Affected endpoint and parameter
  - Proof: full HTTP request + response
  - Evidence: what in the response confirmed this
  - Fix Guide: all 3 layers

━━━ RECOMMENDATIONS PRIORITY LIST ━━━━
[Ordered by CVSS score — fix these first]

━━━ SCAN METADATA ━━━━━━━━━━━━━━━━━━━
[Scan config, timing, modules run]
```

### Export Formats

- **View in Dashboard** — Default. Interactive, filterable.
- **Download PDF** — Using `pdfkit` Node.js library (free). For sharing with professors/clients.
- **Download JSON** — Machine-readable. For CI/CD integration or other tools.
- **Download Markdown** — For pasting into GitHub issues or README security sections.
- **Download CSV** — Vulnerability list only. For tracking in spreadsheets.

---

## 13. System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  FRONTEND (React + Tailwind CSS)                 │
│    Landing → OTP Verify → Dashboard → Scan → Results → Compare  │
│                    Mobile Responsive, Hacker Theme               │
└───────────────────────────┬──────────────────────────────────────┘
                            │ HTTPS REST API + SSE (live updates)
                            │ JWT in httpOnly cookie
┌───────────────────────────▼──────────────────────────────────────┐
│                   BACKEND (Node.js + Express)                    │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Auth Routes │  │ Scan Routes  │  │  Report Routes        │   │
│  │ OTP + JWT   │  │              │  │                       │   │
│  └─────────────┘  └──────┬───────┘  └──────────────────────┘   │
│                          │                                       │
│              ┌───────────▼──────────────┐                        │
│              │   Scan Orchestrator      │                        │
│              │   Creates BullMQ jobs    │                        │
│              └───────────┬──────────────┘                        │
└──────────────────────────┼───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│              BULLMQ JOB QUEUE (backed by Redis)                  │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Crawl Q  │ │ Fuzz Q   │ │ Analyze Q│ │ Report Q │           │
│  │Priority:1│ │Priority:2│ │Priority:3│ │Priority:4│           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│              FUZZING ENGINE (BullMQ Workers)                     │
│                                                                  │
│  [Worker 1]     [Worker 2]     [Worker 3]     [Worker 4]        │
│  Crawler        Passive        Exposed         Payload           │
│  Module         Analyzer       Files Scanner   Fuzzer            │
│                                                                  │
│  [Worker 5]     [Worker 6]                                       │
│  Auth Tester    Tech                                             │
│                 Fingerprinter                                    │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                        DATA LAYER                                │
│                                                                  │
│   MongoDB                          Redis                         │
│   ├── users                        ├── OTP store (10min TTL)    │
│   ├── targets                      ├── BullMQ queues            │
│   ├── scans                        ├── Rate limit counters      │
│   ├── endpoints                    └── Payload cache            │
│   ├── vulnerabilities                                            │
│   ├── payloads (seeded from tools)                              │
│   └── reports                                                    │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                   DOCKER COMPOSE                                 │
│   frontend:3000  backend:5000  mongodb:27017  redis:6379         │
│   fuzzer-worker (auto-scales with concurrency config)            │
└──────────────────────────────────────────────────────────────────┘
```

---

## 14. Tech Stack

### Frontend

| Technology | Version | Purpose | Cost |
|---|---|---|---|
| React | 18+ | UI framework | Free |
| Tailwind CSS | 3+ | Styling | Free |
| React Router | 6+ | Client-side routing | Free |
| React Query (TanStack) | 5+ | Server state, auto-refetch for live scan | Free |
| Recharts | Latest | Charts for CVSS scores, scan comparison, security score trend | Free |
| Lucide React | Latest | Icon library (hacker-appropriate icons) | Free |
| Framer Motion | Latest | Animations for vulnerability cards appearing live | Free |

### Backend

| Technology | Version | Purpose | Cost |
|---|---|---|---|
| Node.js | 20+ | Runtime | Free |
| Express | 4+ | REST API server | Free |
| BullMQ | Latest | Job queues for all 6 scan modules | Free |
| Nodemailer | Latest | OTP email sending via Gmail SMTP | Free |
| jsonwebtoken | Latest | JWT creation and verification | Free |
| bcryptjs | Latest | Not used for passwords but for OTP hashing before Redis storage | Free |
| axios | Latest | HTTP requests to target during fuzzing | Free |
| cheerio | Latest | HTML parsing (server-side jQuery) | Free |
| pdfkit | Latest | PDF report generation | Free |
| mongoose | Latest | MongoDB ODM | Free |
| ioredis | Latest | Redis client | Free |
| cors | Latest | CORS config for frontend | Free |
| helmet | Latest | Security headers for SmartFuzz itself | Free |

### Infrastructure

| Technology | Purpose | Cost |
|---|---|---|
| MongoDB | Primary database | Free (local via Docker) |
| Redis | BullMQ queue backend + OTP store + cache | Free (local via Docker) |
| Docker | Containerization | Free |
| Docker Compose | Multi-container orchestration | Free |

---

## 15. Database Design

### Collection: `users`
```json
{
  "_id": "ObjectId",
  "email": "string (unique)",
  "createdAt": "Date",
  "lastLoginAt": "Date",
  "totalScans": "number"
}
```

### Collection: `targets`
```json
{
  "_id": "ObjectId",
  "userId": "ObjectId",
  "domain": "string (e.g. myapp.com)",
  "fullUrl": "string (e.g. https://myapp.com)",
  "firstScannedAt": "Date",
  "lastScannedAt": "Date",
  "totalScans": "number",
  "scanIds": ["ObjectId"],
  "latestSecurityScore": "number",
  "scoreHistory": [
    { "scanId": "ObjectId", "score": "number", "date": "Date" }
  ]
}
```

### Collection: `scans`
```json
{
  "_id": "ObjectId",
  "userId": "ObjectId",
  "targetId": "ObjectId",
  "targetUrl": "string",
  "scanNumber": "number (1, 2, 3... per target)",
  "status": "queued | crawling | scanning | analyzing | completed | failed",
  "config": {
    "maxDepth": "number",
    "rateLimit": "number",
    "concurrency": "number",
    "modules": ["crawler", "passive", "exposedFiles", "fuzzer", "auth", "fingerprint"]
  },
  "progress": {
    "endpointsFound": "number",
    "endpointsScanned": "number",
    "payloadsSent": "number",
    "vulnerabilitiesFound": "number"
  },
  "stats": {
    "totalEndpoints": "number",
    "totalPayloadsSent": "number",
    "criticalCount": "number",
    "highCount": "number",
    "mediumCount": "number",
    "lowCount": "number",
    "securityScore": "number",
    "startTime": "Date",
    "endTime": "Date",
    "durationSeconds": "number"
  },
  "comparisonWithPrevious": {
    "fixed": ["vulnId"],
    "new": ["vulnId"],
    "persists": ["vulnId"],
    "regressed": ["vulnId"]
  },
  "createdAt": "Date"
}
```

### Collection: `vulnerabilities`
```json
{
  "_id": "ObjectId",
  "scanId": "ObjectId",
  "targetId": "ObjectId",
  "type": "sqli | xss | rce | path_traversal | idor | csrf | ssrf | xxe | ssti | open_redirect | broken_auth | missing_headers | cors | exposed_file | sensitive_data | ssl | cookie | clickjacking | version_disclosure | command_injection | nosql_injection | directory_listing",
  "subtype": "error_based | time_based | boolean_based | reflected | stored | blind",
  "severity": "critical | high | medium | low | info",
  "cvssScore": "number (0.0–10.0)",
  "cvssVector": "string (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
  "cvssMetrics": {
    "attackVector": "N|A|L|P",
    "attackComplexity": "L|H",
    "privilegesRequired": "N|L|H",
    "userInteraction": "N|R",
    "scope": "U|C",
    "confidentiality": "N|L|H",
    "integrity": "N|L|H",
    "availability": "N|L|H"
  },
  "endpoint": "string (URL)",
  "method": "GET|POST|PUT|DELETE",
  "parameter": "string",
  "payload": "string",
  "evidence": "string (what in response confirmed this)",
  "request": {
    "url": "string",
    "method": "string",
    "headers": "object",
    "body": "string"
  },
  "response": {
    "statusCode": "number",
    "headers": "object",
    "body": "string (truncated to 2000 chars)",
    "responseTimeMs": "number"
  },
  "verificationStatus": "unverified | verified_fixed | verified_persists",
  "lastVerifiedAt": "Date",
  "discoveredAt": "Date"
}
```

### Collection: `payloads`
```json
{
  "_id": "ObjectId",
  "source": "seclists | payloadsallthethings | fuzzdb | custom",
  "type": "sqli | xss | rce | path_traversal | ...",
  "value": "string",
  "encoding": "plain | url | base64 | html",
  "successCount": "number",
  "testedCount": "number",
  "tags": ["string"]
}
```

### Collection: `reports`
```json
{
  "_id": "ObjectId",
  "scanId": "ObjectId",
  "targetId": "ObjectId",
  "generatedAt": "Date",
  "summary": {
    "critical": "number",
    "high": "number",
    "medium": "number",
    "low": "number",
    "securityScore": "number"
  },
  "pdfPath": "string (local file path)",
  "jsonContent": "object"
}
```

---

## 16. API Design

### Auth
```
POST  /api/auth/send-otp          Body: {email}
POST  /api/auth/verify-otp        Body: {email, otp} → returns JWT cookie
POST  /api/auth/logout            Clears JWT cookie
GET   /api/auth/me                Returns current user (JWT protected)
```

### Targets
```
GET   /api/targets                All targets for current user
GET   /api/targets/:id            Single target with scan history
DELETE /api/targets/:id           Delete target and all its scans
```

### Scans
```
POST  /api/scans                  Body: {url, config} → starts scan
GET   /api/scans/:id              Scan status + progress
GET   /api/scans/:id/stream       SSE stream for live progress events
POST  /api/scans/:id/rescan       Trigger rescan of same target
GET   /api/scans/:id/compare/:id2 Compare two specific scans
DELETE /api/scans/:id             Cancel/delete scan
```

### Vulnerabilities
```
GET   /api/scans/:id/vulnerabilities          All vulns for a scan
GET   /api/scans/:id/vulnerabilities/:vulnId  Single vuln details
POST  /api/vulnerabilities/:id/verify         Verify fix (rescan endpoint)
```

### Reports
```
GET   /api/scans/:id/report                   Report JSON
GET   /api/scans/:id/report/pdf               Download PDF
GET   /api/scans/:id/report/csv               Download CSV
GET   /api/scans/:id/report/markdown          Download Markdown
```

### Comparison
```
GET   /api/targets/:id/comparison             Full scan history comparison for a target
GET   /api/targets/:id/score-history          Security score over time (for chart)
```

---

## 17. UI/UX Design System

### Design Philosophy

SmartFuzz is a hacker's tool. The UI must feel like it was built inside a terminal — dark, precise, fast, with just enough visual intensity to feel alive. Think: the scan results screen in a cyberpunk film. Every element has purpose. Nothing is decorative without reason.

**Core principles:**
- Dark by default, always — no light mode
- Monospace fonts for technical data (payloads, requests, responses)
- Sans-serif for UI chrome and headings
- Green/red binary storytelling — found it, fixed it
- Motion that feels like data processing — not playful, not corporate
- Information density — show more, scroll less
- Every screen works on mobile without losing meaning

### Color System

```
Background:     #0a0a0f  (near black, slight blue tint)
Surface:        #111118  (cards, panels)
Surface Hover:  #1a1a25  (interactive state)
Border:         #1e1e2e  (subtle separators)

Primary:        #00ff88  (terminal green — primary actions, found vulns)
Primary Dim:    #00cc6a  (hover states)
Secondary:      #7c3aed  (purple — secondary actions, scan running)

Critical:       #ff3333  (red — critical severity)
High:           #ff6b00  (orange — high severity)
Medium:         #f5c518  (yellow — medium severity)
Low:            #3b82f6  (blue — low severity)
Info:           #6b7280  (grey — informational)
Fixed:          #00ff88  (green — vulnerability fixed)

Text Primary:   #e2e8f0  (near white)
Text Secondary: #94a3b8  (muted)
Text Muted:     #475569  (very muted)
Text Code:      #00ff88  (terminal green for payloads, code)

Scan Running:   #7c3aed  (purple pulse animation)
```

### Typography

```
Display / Headings:  "JetBrains Mono" or "Space Mono" — monospace, hacker feel
Body / UI Text:      "Inter" or "DM Sans" — clean, readable
Code / Payloads:     "JetBrains Mono" — all request/response/payload data
```

### Motion

- Vulnerability cards animate in as they are discovered (slide up + fade in)
- CVSS score bar animates from 0 to final score on load
- Scan progress pulses with a running glow on the active step
- Counter numbers count up (0 → 47 endpoints) rather than snapping
- Comparison table rows fade between states
- No loading spinners — use skeleton screens instead

### Component Patterns

**Vulnerability Card:**
```
┌──────────────────────────────────────────────┐
│ [🔴 CRITICAL]    SQL Injection        [10.0] │
│ ██████████████████████████████████ Critical  │
│ POST /api/login • parameter: username        │
│                                              │
│ [View Details]  [View Fix]  [Verify Fix]     │
└──────────────────────────────────────────────┘
```

**Live Scan Terminal Feed:**
```
┌──────────────────────────────────────────────┐
│ > Crawling https://target.com...             │
│ > Found 47 endpoints, 183 parameters         │
│ > Launching 6 scan modules simultaneously    │
│ > [■■■■■■■□□□□□□□] 54% — 6,234 payloads sent│
│ > 🔴 FOUND: SQL Injection on /api/login      │
│ > 🟠 FOUND: XSS on /search?q=               │
│ > Scanning...                                │
└──────────────────────────────────────────────┘
```

---

## 18. Page-by-Page UI Breakdown

### Page 1: Landing / Verify Page

Single-focus screen. Email input, OTP step, then into dashboard. No marketing. No hero section. Just the tool.

```
[SmartFuzz logo — terminal cursor blinking]

"Enter your email to continue"
[ your@email.com                    ]  [→]

After OTP sent:
"Enter the 6-digit code sent to your@email.com"
[ _ _ _ _ _ _ ]

"Code expires in 9:47"
[Resend]
```

Design: Full dark screen, centered, minimal. Green accent on active inputs.

---

### Page 2: Dashboard

First thing the user sees after verifying. If they have no scans: prompt to scan. If they have scans: show history.

**Top section — New Scan:**
```
┌─────────────────────────────────────────────────────┐
│  TARGET URL                                         │
│  [ https://                              ] [SCAN →] │
│  ⚠ Only scan targets you own or have permission for │
└─────────────────────────────────────────────────────┘
```

**Below — Scan History (if exists):**
```
RECENT SCANS                                [View All]
┌────────────────────────────────────────────────────┐
│ myapp.com          Scan #3   23/100 🔴  Nov 24     │
│ 3 Critical · 2 High · 1 Medium          [→ View]   │
├────────────────────────────────────────────────────┤
│ testsite.com       Scan #1   71/100 🟡  Nov 18     │
│ 0 Critical · 1 High · 3 Medium          [→ View]   │
└────────────────────────────────────────────────────┘
```

**Stats Cards (if scans exist):**
```
[Total Scans: 5] [Vulns Found: 23] [Fixed: 14] [Targets: 2]
```

---

### Page 3: Active Scan / Live Monitor

Most important page. User watches the scan happen in real time.

**Top: Target + Status**
```
Scanning: https://myapp.com
Scan #3 · Started 2 min ago · 6 modules running
[■■■■■■■■■□□] 73%
```

**Left Column: Module Status**
```
MODULES
● Crawler            ✅ Complete — 47 endpoints
● Passive Analyzer   ✅ Complete — 3 issues
● Exposed Files      ✅ Complete — 2 found
● Payload Fuzzer     ⚡ Running — 8,234 sent
● Auth Tester        ⚡ Running
● Fingerprinter      ✅ Complete — Express 4.17
```

**Right Column: Live Vulnerability Feed**
```
LIVE FINDINGS                              [9 found]
─────────────────────────────────────────────────────
🔴 10.0  SQL Injection          /api/login   2m ago
🟠 7.5   Path Traversal         /file/load   1m ago
🟡 5.3   Missing CSP Header     (global)     3m ago
🟡 5.3   Version Disclosure     (global)     3m ago
🔵 4.3   Insecure Cookie        /            4m ago
...animating in as found...
```

**Bottom: Terminal Log**
```
> [14:32:01] Crawling started — depth 3
> [14:32:04] Found 47 endpoints, 183 parameters
> [14:32:05] Payload Fuzzer started — 6 workers
> [14:34:22] 🔴 SQL Injection confirmed — POST /api/login
> [14:35:01] Generating mutation variants...
> [14:36:44] Scan complete — report generating...
```

---

### Page 4: Scan Results

Full vulnerability report for a completed scan.

**Header: Security Score**
```
https://myapp.com — Scan #3 — Nov 24, 2024

SECURITY SCORE
     23
   ────── / 100          🔴 Critical Risk

Critical: 3  High: 2  Medium: 3  Low: 1

[Download PDF] [Download CSV] [Rescan →]
```

**Vulnerability Table (sortable, filterable):**
```
Filter: [All ▼]  [Critical ▼]  [Search...]

CVSS   TYPE                ENDPOINT           SEVERITY
10.0   SQL Injection       POST /api/login    🔴 CRITICAL  [→]
10.0   Command Injection   POST /api/exec     🔴 CRITICAL  [→]
9.0    Stored XSS          POST /comment      🔴 CRITICAL  [→]
7.5    Path Traversal      GET /file          🟠 HIGH      [→]
7.5    Exposed /.env       GET /.env          🟠 HIGH      [→]
6.1    Reflected XSS       GET /search        🟡 MEDIUM    [→]
5.3    Missing CSP         (passive)          🟡 MEDIUM    [→]
5.3    Version Disclosure  (passive)          🟡 MEDIUM    [→]
4.3    Insecure Cookie     (passive)          🔵 LOW       [→]
```

**Vulnerability Detail Side Panel (on click):**
```
┌──────────────────────────────────────────────────────┐
│ 🔴 SQL Injection (Error-based)           CVSS: 10.0 │
│ POST /api/login • parameter: username               │
│                                                      │
│ CVSS BREAKDOWN                                       │
│ Attack Vector    ████  Network                       │
│ Complexity       ██░░  Low                           │
│ Privileges       ██░░  None                          │
│ User Interaction ██░░  None                          │
│ Confidentiality  ████  High                          │
│ Integrity        ████  High                          │
│ Availability     ████  High                          │
│                                                      │
│ PROOF                                                │
│ Payload: ' OR '1'='1' --                            │
│ Evidence: MySQL error in response                    │
│                                                      │
│ [REQUEST ▼]  [RESPONSE ▼]                           │
│                                                      │
│ [HOW TO FIX →]          [VERIFY FIX →]             │
└──────────────────────────────────────────────────────┘
```

---

### Page 5: Fix Guide

Full-screen fix guide for one vulnerability. Clean, step-by-step, code blocks.

Three tabs: `WHAT IS THIS` | `HOW TO FIX` | `VERIFY`

Code blocks use monospace font with syntax highlighting. Language switcher for fix examples (Node.js / PHP / Python).

After reading: "Mark as Fixed" button → triggers Verify Fix flow.

---

### Page 6: Scan Comparison

Side-by-side or timeline comparison of all scans for a target.

**Header:**
```
https://myapp.com — Scan History
Scans: #1 (Nov 10) · #2 (Nov 17) · #3 (Nov 24)
```

**Security Score Trend (Line Chart):**
```
Score
100 |
 75 |
 50 |                              ●  52
 25 |          ●  23         ●  45
  0 |______________________________
      Scan 1       Scan 2       Scan 3
```

**Comparison Table:**
```
VULNERABILITY          #1(Nov10)  #2(Nov17)  #3(Nov24)  STATUS
SQL Injection          🔴 10.0    ✅ Fixed   ✅ Fixed    ✅ FIXED
Stored XSS             🔴 9.0     🔴 9.0     ✅ Fixed    ✅ FIXED
Path Traversal         🟠 7.5     🟠 7.5     🟠 7.5      🔴 PERSISTS
IDOR /user/{id}        🟠 8.1     🟠 8.1     🟠 8.1      🔴 PERSISTS
Missing CSP            🟡 5.3     ✅ Fixed   ✅ Fixed    ✅ FIXED
Reflected XSS          —          🆕 6.1     🆕 6.1      🆕 NEW
Exposed /.env          —          —          🔴 7.5      🆕 NEW

TOTALS                 9 vulns    7 vulns    6 vulns
SCORE                  23/100     45/100     52/100      📈 +29
```

**Filter buttons:** [All] [Fixed] [Persists] [New] [Regressed]

---

### Page 7: Target History

All scans ever run by the user. Grouped by target domain.

Each target shows: domain, number of scans, latest score, trend arrow (improving / worsening / stable), last scan date.

Click any target → goes to Scan Comparison for that target.

---

## 19. Mobile Responsiveness

SmartFuzz must work completely on mobile. A developer checking their site from their phone must have full access to all features.

### Breakpoints

```
Mobile:   320px – 640px   (single column, bottom nav)
Tablet:   641px – 1024px  (two column where needed)
Desktop:  1025px+         (full layout)
```

### Mobile-Specific Adaptations

**Navigation:** Bottom tab bar on mobile (Dashboard, Scan, History, Report) instead of sidebar.

**Scan Results Page:** Vulnerability cards stack vertically. CVSS score shown as colored badge. Swipe card right to view details.

**Live Monitor:** Module status collapses to status dots. Terminal log is collapsible. Vulnerability feed is full width.

**Comparison Table:** Horizontally scrollable. Fixed first column (vulnerability name), scrollable scan columns.

**Fix Guide:** Full screen, tab-based. Code blocks horizontally scrollable.

**Touch Interactions:**
- Tap vulnerability card → slide-up detail panel
- Swipe left on card → quick actions (Fix Guide, Verify)
- Pull to refresh on scan list
- Long-press on payload → copy to clipboard

---

## 20. Testing Strategy

### Test Targets (All Free, All Dockerized)

```yaml
# Add to docker-compose.yml under testing profile
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports: ["8081:80"]
    profiles: ["testing"]

  webgoat:
    image: webgoat/goat-and-wolf
    ports: ["8082:8080"]
    profiles: ["testing"]

  nodegoat:
    build: ./testing/nodegoat
    ports: ["8083:4000"]
    profiles: ["testing"]

  bwapp:
    image: raesene/bwapp
    ports: ["8084:80"]
    profiles: ["testing"]
```

```bash
docker-compose --profile testing up
# SmartFuzz on :3000, all targets running locally
```

### Test Plan

**Round 1 — Detection Rate Test**
- Run SmartFuzz on DVWA (Low security)
- Compare findings against DVWA's known vulnerability list
- Target: > 85% detection rate
- Document: which vulnerabilities found, which missed, why

**Round 2 — False Positive Test**
- Run SmartFuzz on a known-clean application (basic Express app with no vulnerabilities)
- Goal: 0 false positives
- Document any false positives and the rule that caused them

**Round 3 — Mutation Engine Test**
- Run on DVWA with Medium security (basic filter enabled)
- Check if mutation engine bypasses the filter and still finds SQLi/XSS
- Compare: Low security detection rate vs Medium security detection rate

**Round 4 — Comparison Feature Test**
- Scan DVWA (Low) → manual fix one vulnerability → rescan → verify comparison shows it as Fixed

**Round 5 — Performance Test**
- Measure full scan duration on DVWA at rate limit 10 req/sec
- Measure memory and CPU usage during scan
- Goal: full scan under 15 minutes, stable memory

### Metrics For Project Report

| Metric | Formula | Target |
|---|---|---|
| Detection Rate | Vulns found ÷ Known vulns × 100 | > 85% |
| False Positive Rate | Wrong alerts ÷ Total alerts × 100 | < 5% |
| OWASP Coverage | Categories detected ÷ 10 × 100 | > 80% |
| Scan Duration | Full DVWA scan time | < 15 min |
| Fix Guide Coverage | Vuln types with fix guides ÷ Total types | 100% |

---

## 21. Project Folder Structure

```
smartfuzz/
│
├── docker-compose.yml               # All services
├── docker-compose.testing.yml       # Test target apps
├── .env.example
├── README.md
│
├── frontend/                        # React + Tailwind
│   ├── public/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── VerifyPage.jsx       # OTP entry
│   │   │   ├── DashboardPage.jsx    # Home + new scan
│   │   │   ├── ScanMonitorPage.jsx  # Live scan view
│   │   │   ├── ScanResultsPage.jsx  # Full results
│   │   │   ├── FixGuidePage.jsx     # Fix walkthrough
│   │   │   ├── ComparisonPage.jsx   # Scan comparison
│   │   │   └── HistoryPage.jsx      # All targets
│   │   ├── components/
│   │   │   ├── VulnerabilityCard.jsx
│   │   │   ├── CVSSMeter.jsx
│   │   │   ├── ScanTerminal.jsx
│   │   │   ├── ComparisonTable.jsx
│   │   │   ├── SecurityScoreChart.jsx
│   │   │   ├── ModuleStatusPanel.jsx
│   │   │   └── FixGuidePanel.jsx
│   │   ├── hooks/
│   │   │   ├── useScanSSE.js        # SSE live updates
│   │   │   └── useScans.js          # React Query hooks
│   │   ├── api/
│   │   │   └── client.js            # axios instance
│   │   └── styles/
│   │       └── globals.css
│   ├── tailwind.config.js
│   └── Dockerfile
│
├── backend/                         # Node.js + Express
│   ├── src/
│   │   ├── routes/
│   │   │   ├── auth.routes.js
│   │   │   ├── scan.routes.js
│   │   │   ├── target.routes.js
│   │   │   ├── vulnerability.routes.js
│   │   │   └── report.routes.js
│   │   ├── controllers/
│   │   ├── middleware/
│   │   │   ├── auth.middleware.js   # JWT verify
│   │   │   └── rateLimit.middleware.js
│   │   ├── models/
│   │   │   ├── User.js
│   │   │   ├── Target.js
│   │   │   ├── Scan.js
│   │   │   ├── Vulnerability.js
│   │   │   ├── Payload.js
│   │   │   └── Report.js
│   │   ├── services/
│   │   │   ├── email.service.js     # Nodemailer OTP
│   │   │   ├── report.service.js    # PDF/CSV/MD generation
│   │   │   └── comparison.service.js
│   │   ├── queue/
│   │   │   └── bullmq.config.js
│   │   └── app.js
│   └── Dockerfile
│
├── fuzzer/                          # Scanning Engine
│   ├── src/
│   │   ├── workers/
│   │   │   ├── crawlerWorker.js
│   │   │   ├── passiveWorker.js
│   │   │   ├── exposedFilesWorker.js
│   │   │   ├── fuzzWorker.js
│   │   │   ├── authWorker.js
│   │   │   └── fingerprintWorker.js
│   │   ├── modules/
│   │   │   ├── crawler.js
│   │   │   ├── passiveAnalyzer.js
│   │   │   ├── exposedFilesScanner.js
│   │   │   ├── paramClassifier.js
│   │   │   ├── payloadEngine.js
│   │   │   ├── httpSender.js
│   │   │   ├── responseAnalyzer.js
│   │   │   ├── mutationEngine.js
│   │   │   ├── authTester.js
│   │   │   ├── techFingerprinter.js
│   │   │   └── cvssCalculator.js
│   │   └── knowledge/
│   │       ├── fixGuides.json       # All fix guides per vuln type
│   │       ├── cveDatabase.json     # Local CVE list for version matching
│   │       ├── sensitivePaths.json  # 150+ paths for exposed files scan
│   │       └── zapRules.js          # ZAP passive scan rules in JS
│   └── Dockerfile
│
├── payloads/                        # Cloned from GitHub at setup
│   ├── seclists/                    # danielmiessler/SecLists
│   ├── patt/                        # swisskyrepo/PayloadsAllTheThings
│   ├── fuzzdb/                      # fuzzdb-project/fuzzdb
│   └── seed.js                      # Loads all into MongoDB
│
└── docs/
    └── SmartFuzz_PRD.md             # This document
```

---

## 22. Development Phases

### Phase 1 — Foundation (Week 1–2)
- [ ] Initialize monorepo with Docker Compose
- [ ] MongoDB + Redis running in Docker
- [ ] OTP email system (Nodemailer + Gmail SMTP)
- [ ] JWT auth middleware
- [ ] Basic React shell with routing and color system
- [ ] Payload seeding script (clone repos + load into MongoDB)

### Phase 2 — Crawler & Passive (Week 3–4)
- [ ] Crawler module (axios + cheerio)
- [ ] Passive Analyzer (headers, cookies, SSL)
- [ ] Exposed Files Scanner (150 paths)
- [ ] Tech Fingerprinter
- [ ] BullMQ pipeline for these 3 modules
- [ ] Test against DVWA — verify endpoints discovered

### Phase 3 — Fuzzing Engine (Week 5–7)
- [ ] Parameter Classifier (rule engine)
- [ ] Payload Engine (MongoDB query by attack type)
- [ ] HTTP Sender (rate-limited, concurrent)
- [ ] Response Analyzer (ZAP rules + heuristics)
- [ ] Mutation Engine
- [ ] Auth Tester
- [ ] Full pipeline working end-to-end

### Phase 4 — CVSS & Reports (Week 8–9)
- [ ] CVSS calculator (all 24 vulnerability types)
- [ ] Security score calculation
- [ ] Fix Guide knowledge base (all 22 types)
- [ ] Report Generator (JSON + PDF + CSV + Markdown)
- [ ] Comparison Engine (diff algorithm across scans)
- [ ] Verify Fix feature (single-endpoint rescan)

### Phase 5 — Frontend (Week 9–11)
- [ ] All 7 pages built with hacker theme
- [ ] SSE integration for live scan monitor
- [ ] CVSS breakdown component
- [ ] Comparison table with filters
- [ ] Security score trend chart
- [ ] Fix guide page with code tabs
- [ ] Full mobile responsiveness

### Phase 6 — Testing & Polish (Week 12)
- [ ] Full test against DVWA, WebGoat, NodeGoat, bWAPP
- [ ] Document detection rate metrics
- [ ] Performance tuning
- [ ] Final Docker Compose build
- [ ] Project report and presentation prep

---

*SmartFuzz — Product Requirements Document v2.0*
*Zero cost. Zero subscriptions. Zero external AI APIs.*
*Runs entirely on your machine.*
