# SmartFuzz — AI-Free Intelligent Web Application Fuzzer
### Complete Project Context Document
> Version 1.0 | Final Year Project | Sinhgad College of Engineering, Pune

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [The Problem We Are Solving](#2-the-problem-we-are-solving)
3. [What We Are NOT Doing](#3-what-we-are-not-doing)
4. [What We ARE Building](#4-what-we-are-building)
5. [Core Concepts Explained](#5-core-concepts-explained)
6. [System Architecture](#6-system-architecture)
7. [Tech Stack & Why Each Tool](#7-tech-stack--why-each-tool)
8. [Open Source Tools We Integrate](#8-open-source-tools-we-integrate)
9. [Module-by-Module Breakdown](#9-module-by-module-breakdown)
10. [Database Design](#10-database-design)
11. [API Design](#11-api-design)
12. [Frontend Design](#12-frontend-design)
13. [Security & Ethics](#13-security--ethics)
14. [Project Phases & Timeline](#14-project-phases--timeline)
15. [What Makes This Original](#15-what-makes-this-original)

---

## 1. Project Overview

**SmartFuzz** is a full-stack, open-source web application fuzzer built entirely without any paid AI APIs or LLM subscriptions. It automatically discovers vulnerabilities in web applications by intelligently throwing thousands of crafted malicious inputs (called *payloads*) at a target and analyzing how the application responds.

The system is built on a rule-based intelligence engine powered by five proven open-source tools, a mutation engine for payload evolution, and a real-time response anomaly detector — all running locally, offline, at zero cost.

**In one line:**
> SmartFuzz is a smart, adaptive, context-aware web vulnerability scanner that works like a seasoned penetration tester — without needing the internet, an API key, or any paid subscription.

---

## 2. The Problem We Are Solving

### 2.1 The Cyber Attack Reality

Web applications are the #1 attack target globally. Every year:
- **SQL Injection, XSS, and RCE** remain in the OWASP Top 10 despite being known for decades
- Developers keep shipping vulnerable code because testing is manual, slow, and expensive
- Startups, students, and small organizations cannot afford enterprise security tools

### 2.2 Why Existing Tools Fail

| Tool | Problem |
|---|---|
| **Burp Suite Pro** | Costs $449/year, closed source |
| **OWASP ZAP** | Free but complex setup, outdated UI, high false positives |
| **Nikto** | Command-line only, no adaptive logic, no dashboard |
| **Generic LLM-based fuzzers** | Just wrappers around ChatGPT/Gemini — the AI does all the thinking, not the system itself |
| **sqlmap / wfuzz** | Excellent but single-purpose, no unified pipeline, no visual reporting |

### 2.3 The Real Gap

No existing **free, open-source tool** combines:
- Intelligent parameter-aware payload selection
- Real-time adaptive feedback (learns from responses mid-scan)
- A modern visual dashboard with severity reports
- A unified pipeline from crawling → fuzzing → reporting

**That gap is exactly what SmartFuzz fills.**

---

## 3. What We Are NOT Doing

This is important to state clearly:

- ❌ We are NOT calling Gemini, ChatGPT, or any external LLM API
- ❌ We are NOT training any ML model
- ❌ We are NOT paying for any subscription or service
- ❌ We are NOT building another chatbot wrapper
- ❌ We are NOT relying on any cloud service during fuzzing

Everything runs **100% locally on the user's machine.**

---

## 4. What We ARE Building

A full-stack web application with the following capabilities:

### 4.1 Core Capabilities

1. **Web Crawler** — Automatically discovers all forms, input fields, query parameters, API endpoints, and hidden fields in a target website

2. **Parameter Classifier** — A rule-based engine that reads parameter names (`user_id`, `search`, `file_path`, `email`, etc.) and determines *what type of attack* is most likely to work against each one

3. **Payload Engine** — Pulls from 5 open-source payload databases (SecLists, PayloadsAllTheThings, FuzzDB, etc.) and selects the right payload category for each parameter

4. **Mutation Engine** — Takes a payload that got an "interesting" response and automatically generates 10–20 variants (URL-encoded, base64, case-swapped, comment-injected) to bypass filters

5. **Fuzzing Engine** — Concurrently fires all payloads at the target using async HTTP requests, respecting rate limits to avoid DoS

6. **Response Analyzer** — Analyzes every HTTP response using ZAP's open-source passive scan rules and custom heuristics to classify if a vulnerability was found

7. **Adaptive Feedback Loop** — Tracks which payload types got high-interest responses and prioritizes similar payloads in subsequent rounds

8. **Vulnerability Reporter** — Generates structured reports with severity levels (Critical/High/Medium/Low), proof-of-concept payloads, and remediation advice from a local knowledge base

9. **Real-time Dashboard** — React frontend showing live scan progress, found vulnerabilities, response heatmaps, and downloadable reports

### 4.2 Vulnerabilities Detected

- SQL Injection (Error-based, Boolean-based, Time-based)
- Cross-Site Scripting — XSS (Reflected, Stored)
- Remote Code Execution (RCE)
- Path Traversal / Directory Traversal
- Authentication Bypass
- Command Injection
- Open Redirect
- HTTP Header Injection

---

## 5. Core Concepts Explained

### 5.1 What is Fuzzing?

Fuzzing means automatically feeding a program unexpected, malformed, or malicious input to see if it breaks. For web apps, this means sending payloads like:

```
' OR 1=1 --          ← SQL Injection attempt
<script>alert(1)</script>   ← XSS attempt
../../etc/passwd     ← Path Traversal attempt
; ls -la             ← Command Injection attempt
```

If the app responds abnormally — crashes, leaks error messages, changes behavior — a vulnerability likely exists.

### 5.2 What is Context-Aware Fuzzing?

A dumb fuzzer sends ALL payloads to ALL fields. A smart fuzzer sends the **right payload to the right field.**

Example:
- A field named `user_id` that takes numbers → try SQL injection, not XSS
- A field named `redirect_url` → try Open Redirect payloads
- A field named `template` or `file` → try Path Traversal

SmartFuzz's parameter classifier does this mapping automatically.

### 5.3 What is the Mutation Engine?

When a basic payload like `' OR 1=1 --` gets blocked by a web application firewall (WAF), the mutation engine generates bypass variants:

```
'/**/OR/**/1=1/**/--       ← comment-based space bypass
%27%20OR%201%3D1%20--      ← URL encoded
' oR '1'='1               ← case variation
CHAR(39)+OR+CHAR(49)=CHAR(49) ← char encoding bypass
```

This makes SmartFuzz effective even against applications with basic filtering.

### 5.4 What is the Feedback Loop?

After each round of fuzzing:
1. Responses are scored (500 error = high interest, 200 same = low interest)
2. High-interest payload types are flagged
3. Next round prioritizes similar payloads and their mutations
4. Low-interest payload types are deprioritized

This is a **deterministic priority queue**, not ML — implemented using BullMQ job queues with priority scoring.

---

## 6. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FRONTEND (React + Tailwind)             │
│  Dashboard | Scan Config | Live Results | Reports | Auth    │
└─────────────────────────┬───────────────────────────────────┘
                          │ REST API (JWT Protected)
┌─────────────────────────▼───────────────────────────────────┐
│                   BACKEND (Node.js + Express)               │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Auth Module │  │ Scan Manager │  │  Report Generator │  │
│  │  (JWT)      │  │              │  │                   │  │
│  └─────────────┘  └──────┬───────┘  └───────────────────┘  │
│                          │                                  │
│  ┌───────────────────────▼─────────────────────────────┐   │
│  │              BullMQ Job Queue (Redis)               │   │
│  │  [Crawl Job] → [Classify Job] → [Fuzz Job]          │   │
│  │  → [Analyze Job] → [Mutate Job] → [Report Job]      │   │
│  └───────────────────────┬─────────────────────────────┘   │
└──────────────────────────┼──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   FUZZING ENGINE (Node.js Workers)          │
│                                                             │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │   Crawler    │  │ Param Classifier │  │Payload Engine│  │
│  │  (axios +    │  │  (Rule Engine)   │  │ (SecLists +  │  │
│  │   cheerio)   │  │                  │  │  FuzzDB etc) │  │
│  └──────────────┘  └──────────────────┘  └──────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  HTTP Sender │  │Response Analyzer │  │  Mutation    │  │
│  │  (axios,     │  │ (ZAP Rules +     │  │  Engine      │  │
│  │  concurrent) │  │  Heuristics)     │  │              │  │
│  └──────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                        DATA LAYER                           │
│          MongoDB (scan data)   +   Redis (queues/cache)     │
└─────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   DOCKER (Everything Containerized)         │
│     frontend | backend | mongodb | redis | fuzzer-worker    │
└─────────────────────────────────────────────────────────────┘
```

### 6.1 Data Flow (Step by Step)

```
User enters target URL
        ↓
[1] Crawl Job created in BullMQ
        ↓
[2] Crawler discovers endpoints, forms, params
        ↓
[3] Classify Job — each param gets a type label
        ↓
[4] Payload Engine — loads matching payloads from SecLists/FuzzDB
        ↓
[5] Fuzz Jobs created — one per endpoint (concurrent, rate-limited)
        ↓
[6] HTTP Sender fires payloads at target
        ↓
[7] Response Analyzer scores each response
        ↓
[8] High-interest responses → Mutation Engine generates variants
        ↓
[9] Second-round Fuzz Jobs created with mutated payloads
        ↓
[10] Vulnerabilities confirmed → stored in MongoDB
        ↓
[11] Report Generator creates structured report with remediation
        ↓
[12] Frontend dashboard updates in real-time via polling/SSE
```

---

## 7. Tech Stack & Why Each Tool

### 7.1 Frontend

| Technology | Why |
|---|---|
| **React** | Component-based UI perfect for a live-updating dashboard with scan status, charts, and tables |
| **Tailwind CSS** | Utility-first CSS — fast to build, consistent design, no custom CSS mess |
| **React Query** | Handles server state, auto-refetching for live scan updates |
| **Recharts** | Free charting library for vulnerability distribution graphs |
| **React Router** | Client-side routing for Dashboard / Scans / Reports pages |

### 7.2 Backend

| Technology | Why |
|---|---|
| **Node.js** | Non-blocking I/O — perfect for handling hundreds of concurrent HTTP fuzzing requests |
| **Express.js** | Lightweight, fast REST API framework — no overhead |
| **JWT (JSON Web Tokens)** | Stateless authentication — user logs in, gets a token, every API call is verified without hitting DB each time |
| **BullMQ** | Job queue for managing fuzzing tasks — crawl → classify → fuzz → analyze → report as a pipeline. Handles retries, failures, concurrency |
| **axios + cheerio** | axios for HTTP requests to target, cheerio for HTML parsing (like jQuery for server-side) |

### 7.3 Database & Cache

| Technology | Why |
|---|---|
| **MongoDB** | Schema-flexible — scan results, payloads, vulnerability objects all have variable structures. Perfect fit for security data |
| **Redis** | Powers BullMQ job queues AND caches payload lists so we don't read files from disk on every request |

### 7.4 Infrastructure

| Technology | Why |
|---|---|
| **Docker** | Every service (frontend, backend, MongoDB, Redis, worker) runs in its own container. One command (`docker-compose up`) starts the entire system |
| **Docker Compose** | Orchestrates all containers locally — no Kubernetes complexity needed |

---

## 8. Open Source Tools We Integrate

These are not dependencies we install — we **clone their payload files** and build logic around them.

### Tool 1: SecLists
- **Repo:** `github.com/danielmiessler/SecLists`
- **What we use:** `/Fuzzing/SQLi/`, `/Fuzzing/XSS/`, `/Fuzzing/RCE/` payload text files
- **How:** Loaded into MongoDB at startup as our base payload library
- **Role in pipeline:** Primary payload source for all vulnerability types

### Tool 2: PayloadsAllTheThings
- **Repo:** `github.com/swisskyrepo/PayloadsAllTheThings`
- **What we use:** Bypass technique lists, filter evasion patterns per vulnerability type
- **How:** Used by the Mutation Engine to generate filter-bypass variants
- **Role in pipeline:** Feeds the mutation engine when basic payloads get blocked

### Tool 3: FuzzDB
- **Repo:** `github.com/fuzzdb-project/fuzzdb`
- **What we use:** Attack patterns organized by input type (`integer`, `string`, `filename`, `email`)
- **How:** Maps directly to our parameter classifier output — if classifier says "numeric ID", FuzzDB gives the right patterns
- **Role in pipeline:** Precision payload selection based on parameter type

### Tool 4: Wapiti
- **Repo:** `github.com/wapiti-scanner/wapiti`
- **What we use:** Study its crawler and response analysis source code as architectural reference
- **How:** We read its Python source to understand how a production fuzzer handles crawling, form detection, and response analysis — then implement our own version in Node.js
- **Role in pipeline:** Blueprint for our crawler and analyzer modules

### Tool 5: OWASP ZAP Passive Scan Rules
- **Repo:** `github.com/zaproxy/zap-extensions`
- **What we use:** The regex patterns and heuristics from its passive scanner rules
- **How:** Ported to JavaScript — these are the rules that detect SQL errors in responses, XSS reflections, information leakage, etc.
- **Role in pipeline:** Core of our Response Analyzer — battle-tested detection patterns

---

## 9. Module-by-Module Breakdown

### 9.1 Crawler Module

**Purpose:** Discover all attack surface of the target web application

**Logic:**
1. Start at the target URL
2. Fetch the page HTML using axios
3. Parse with cheerio to find:
   - All `<form>` elements and their `<input>` fields
   - All `<a href>` links (internal only)
   - All query parameters in URLs (`?id=1&name=foo`)
   - All `action` attributes in forms
4. Recursively crawl discovered links up to configured depth
5. Deduplicate endpoints
6. Output: List of `{url, method, params: [{name, type, value}]}` objects

**Respects:** robots.txt optionally, rate limits, max depth config

---

### 9.2 Parameter Classifier Module

**Purpose:** Decide what attack type to try on each parameter

**Logic (Rule Engine):**

```
param name contains ["id", "uid", "user_id", "product_id", "item"]
    → category: NUMERIC_ID → attacks: [SQLi, IDOR]

param name contains ["search", "q", "query", "keyword", "term"]
    → category: SEARCH_FIELD → attacks: [XSS, SQLi]

param name contains ["file", "path", "dir", "folder", "template", "page"]
    → category: FILE_PATH → attacks: [Path Traversal, LFI, RFI]

param name contains ["redirect", "url", "next", "return", "goto"]
    → category: URL_FIELD → attacks: [Open Redirect, SSRF]

param name contains ["email", "mail"]
    → category: EMAIL → attacks: [Header Injection, XSS]

param name contains ["cmd", "exec", "command", "run", "ping"]
    → category: COMMAND → attacks: [RCE, Command Injection]

param name contains ["user", "username", "login", "pass", "password", "auth"]
    → category: AUTH_FIELD → attacks: [Auth Bypass, SQLi]

input type == "hidden"
    → category: HIDDEN → attacks: [CSRF, Parameter Tampering]

default (unknown param)
    → category: GENERIC → attacks: [XSS, SQLi, basic fuzzing]
```

**Output:** Each param tagged with a category and a prioritized attack list

---

### 9.3 Payload Engine Module

**Purpose:** Load the right payloads for each parameter category

**Logic:**
1. Receive classified parameter list from Classifier
2. For each category, query MongoDB payload library:
   - `SQLi` → SecLists SQLi payloads + FuzzDB integer patterns
   - `XSS` → SecLists XSS payloads + PayloadsAllTheThings XSS list
   - `Path Traversal` → FuzzDB traversal patterns
   - `RCE` → PayloadsAllTheThings RCE list
3. Apply smart truncation — don't fire 10,000 payloads at once, prioritize top 100 most-historically-effective ones first
4. Output: `{endpoint, param, payloads: [...]}` job objects → pushed into BullMQ

---

### 9.4 HTTP Sender (Fuzzing Engine Core)

**Purpose:** Actually fire the payloads at the target

**Logic:**
1. Pull fuzz jobs from BullMQ queue
2. For each job: inject the payload into the parameter
3. Send the HTTP request (GET or POST) using axios
4. Respect rate limit (configurable, default 10 req/sec) using token bucket algorithm
5. Collect full response: status code, headers, body, response time
6. Push `{request, response, payload, param}` to Response Analyzer queue

**Concurrency:** BullMQ workers run in parallel — configurable concurrency (default: 5 concurrent fuzzing workers)

---

### 9.5 Response Analyzer Module

**Purpose:** Determine if a response indicates a vulnerability

**Detection Methods (from ZAP rules + custom):**

```
SQL ERROR DETECTION:
  response body contains:
    "you have an error in your sql syntax"
    "warning: mysql"
    "unclosed quotation mark"
    "quoted string not properly terminated"
    "ORA-01756" (Oracle)
    "SQLiteException"
  → Confirmed: SQL Injection (Error-based)

TIME-BASED SQLi:
  response time > 5000ms AND payload contained sleep/waitfor/benchmark
  → Confirmed: SQL Injection (Time-based)

XSS REFLECTION:
  payload string appears unescaped in response body
  → Confirmed: Reflected XSS

PATH TRAVERSAL:
  response body contains "root:x:0:0" OR "daemon:" (unix passwd file)
  response body contains "[boot loader]" (windows)
  → Confirmed: Path Traversal

RCE DETECTION:
  response body contains output of injected command (uid=, Linux version, etc.)
  → Confirmed: RCE

ANOMALY DETECTION (for deeper investigation):
  response status == 500 → HIGH INTEREST
  response size differs from baseline by > 20% → MEDIUM INTEREST
  response time > 3x baseline → MEDIUM INTEREST (possible time-based)
  new error keywords appear → HIGH INTEREST
```

**Output:** Each response scored as `CONFIRMED_VULN`, `HIGH_INTEREST`, `MEDIUM_INTEREST`, or `NOT_VULNERABLE`

---

### 9.6 Mutation Engine Module

**Purpose:** Generate bypass variants when a payload shows HIGH_INTEREST but not confirmed

**Mutation Techniques (from PayloadsAllTheThings):**

```javascript
// For SQL payloads:
mutations = [
  payload.replace(/ /g, '/**/'),           // comment bypass
  payload.replace(/ /g, '%20'),            // URL encode spaces
  payload.replace(/ /g, '+'),              // plus encode
  payload.toUpperCase(),                   // case bypass
  payload.replace(/'/g, '"'),             // quote swap
  encodeURIComponent(payload),            // full URL encode
  Buffer.from(payload).toString('base64'), // base64
  payload.replace('OR', '||'),            // operator swap
  payload.replace('AND', '&&'),
]

// For XSS payloads:
mutations = [
  payload.replace('<', '&lt;'),           // HTML entity (test if decoded)
  payload.replace('<script>', '<ScRiPt>'), // case mix
  payload.replace('<script>', '<scr\x00ipt>'), // null byte
  `javascript:${payload}`,               // protocol bypass
  payload.split('').join('/**/'),        // comment fragmentation
]
```

**Output:** New batch of fuzz jobs with mutated payloads pushed back into BullMQ with HIGH priority

---

### 9.7 Report Generator Module

**Purpose:** Produce a structured, human-readable vulnerability report

**For each confirmed vulnerability, report includes:**
- Vulnerability type and CVE reference
- Severity: Critical / High / Medium / Low (CVSS-based)
- Affected endpoint and parameter
- Proof-of-concept payload that triggered it
- Full HTTP request and response
- Remediation advice (from local knowledge base, not AI)

**Remediation Knowledge Base (hardcoded, evidence-based):**

```
SQLi → Use parameterized queries / prepared statements. 
       Use an ORM. Never concatenate user input into queries.
       
XSS → Encode output using context-appropriate encoding.
      Use Content-Security-Policy headers.
      Sanitize input with libraries like DOMPurify.
      
RCE → Never pass user input to system(), exec(), eval().
      Use allowlists for permitted commands.
      Run application with least-privilege user.
      
Path Traversal → Validate and sanitize file paths.
                 Use path.resolve() and verify it starts with allowed base.
                 Never expose raw file system paths.
```

**Output formats:** JSON (for API consumers) + HTML report (for download)

---

### 9.8 Authentication Module (JWT)

**Purpose:** Secure the SmartFuzz dashboard so only authorized users can run scans

**Flow:**
1. User registers/logs in → server creates JWT token (signed with secret)
2. Token stored in browser (httpOnly cookie or localStorage)
3. Every API call includes Bearer token in Authorization header
4. Express middleware verifies token on protected routes
5. Token expires in 24 hours, refresh token mechanism for longer sessions

**Why needed:** SmartFuzz is a hacking tool. Without auth, anyone on the network could use it to scan unauthorized targets.

---

## 10. Database Design

### MongoDB Collections

#### `users`
```json
{
  "_id": "ObjectId",
  "email": "string",
  "passwordHash": "string (bcrypt)",
  "createdAt": "Date",
  "role": "admin | user"
}
```

#### `scans`
```json
{
  "_id": "ObjectId",
  "userId": "ObjectId (ref: users)",
  "targetUrl": "string",
  "status": "pending | crawling | fuzzing | analyzing | completed | failed",
  "config": {
    "maxDepth": "number",
    "rateLimit": "number (req/sec)",
    "concurrency": "number",
    "selectedAttacks": ["sqli", "xss", "rce", "traversal"]
  },
  "stats": {
    "totalEndpoints": "number",
    "totalPayloadsSent": "number",
    "totalVulnerabilities": "number",
    "startTime": "Date",
    "endTime": "Date"
  },
  "createdAt": "Date"
}
```

#### `endpoints`
```json
{
  "_id": "ObjectId",
  "scanId": "ObjectId (ref: scans)",
  "url": "string",
  "method": "GET | POST | PUT | DELETE",
  "params": [
    {
      "name": "string",
      "type": "string",
      "category": "NUMERIC_ID | SEARCH_FIELD | FILE_PATH | ...",
      "attackTypes": ["sqli", "xss"]
    }
  ]
}
```

#### `vulnerabilities`
```json
{
  "_id": "ObjectId",
  "scanId": "ObjectId (ref: scans)",
  "endpointId": "ObjectId (ref: endpoints)",
  "type": "sqli | xss | rce | traversal | open_redirect | ...",
  "severity": "critical | high | medium | low",
  "param": "string",
  "payload": "string",
  "request": {
    "url": "string",
    "method": "string",
    "headers": "object",
    "body": "string"
  },
  "response": {
    "statusCode": "number",
    "body": "string (truncated)",
    "responseTime": "number (ms)"
  },
  "evidence": "string (what in the response confirmed this)",
  "remediation": "string",
  "confirmedAt": "Date"
}
```

#### `payloads`
```json
{
  "_id": "ObjectId",
  "source": "seclists | payloadsallthethings | fuzzdb | custom",
  "type": "sqli | xss | rce | traversal | ...",
  "value": "string",
  "successCount": "number (incremented when this payload finds a vuln)",
  "tags": ["string"]
}
```

#### `reports`
```json
{
  "_id": "ObjectId",
  "scanId": "ObjectId (ref: scans)",
  "generatedAt": "Date",
  "summary": {
    "critical": "number",
    "high": "number",
    "medium": "number",
    "low": "number"
  },
  "htmlContent": "string",
  "jsonContent": "object"
}
```

---

## 11. API Design

### Auth Routes
```
POST   /api/auth/register       → Create account
POST   /api/auth/login          → Get JWT token
POST   /api/auth/logout         → Invalidate token
GET    /api/auth/me             → Get current user
```

### Scan Routes (JWT Protected)
```
POST   /api/scans               → Create and start new scan
GET    /api/scans               → List all scans for user
GET    /api/scans/:id           → Get scan details + status
DELETE /api/scans/:id           → Cancel/delete scan
GET    /api/scans/:id/progress  → SSE stream for live progress updates
```

### Vulnerability Routes (JWT Protected)
```
GET    /api/scans/:id/vulnerabilities         → All vulns for a scan
GET    /api/scans/:id/vulnerabilities/:vulnId → Single vuln details
```

### Report Routes (JWT Protected)
```
GET    /api/scans/:id/report        → Get report JSON
GET    /api/scans/:id/report/html   → Download HTML report
```

### Payload Routes (JWT Protected)
```
GET    /api/payloads            → List payload library stats
POST   /api/payloads/custom     → Add custom payload
```

---

## 12. Frontend Design

### Pages

**1. Login / Register Page**
- Simple auth form
- JWT stored on login

**2. Dashboard (Home)**
- Total scans run, total vulns found (cards)
- Recent scans list with status badges
- Vulnerability severity distribution chart (Recharts donut chart)
- Quick "New Scan" button

**3. New Scan Page**
- Target URL input
- Scan configuration (depth, rate limit, attack type toggles)
- Start Scan button

**4. Active Scan / Live Monitor Page**
- Real-time progress bar (endpoints crawled, payloads sent)
- Live vulnerability feed (new finds appear as they're discovered)
- Request/response log (scrolling table)
- Stats counters updating in real-time (via SSE)

**5. Scan Results Page**
- Vulnerability table (filterable by type, severity)
- Click any vulnerability → side panel with full request/response + remediation
- Severity breakdown chart
- Download Report button

**6. Reports Page**
- List of all generated reports
- Preview + download HTML report

**7. Payload Library Page**
- View all loaded payloads by source and type
- Add custom payloads
- Stats on most effective payloads

---

## 13. Security & Ethics

### Who Can Use SmartFuzz

SmartFuzz is designed **exclusively for authorized security testing.** This means:
- Testing your own web application
- Testing with written permission from the target owner
- Testing deliberately vulnerable practice applications (DVWA, WebGoat, HackTheBox)

### Built-in Safety Measures

1. **Rate Limiting** — Default max 10 requests/second to avoid DoS
2. **Target Whitelist Mode** — Optional: only allow scans against pre-approved domains
3. **Disclaimer on Scan Start** — User must confirm they have authorization before a scan launches
4. **Audit Log** — Every scan is logged with user ID and timestamp

### Practice Targets (Safe to Test On)

- **DVWA** (Damn Vulnerable Web Application) — Docker image, runs locally
- **OWASP WebGoat** — Docker image, intentionally vulnerable Java app
- **HackTheBox / TryHackMe** — Online platforms with legal vulnerable machines
- **bWAPP** — Buggy Web Application for testing

**The project documentation will explicitly state that unauthorized use is illegal under the IT Act 2000 and Computer Fraud & Abuse Act.**

---

## 14. Project Phases & Timeline

### Phase 1 — Foundation (Weeks 1–3)
- [ ] Initialize monorepo (frontend + backend + docker)
- [ ] MongoDB + Redis setup with Docker Compose
- [ ] User auth (register, login, JWT)
- [ ] Basic React frontend with routing
- [ ] Payload seeding script (load SecLists/FuzzDB into MongoDB)

### Phase 2 — Crawler + Classifier (Weeks 4–5)
- [ ] Build crawler module (axios + cheerio)
- [ ] Build parameter classifier (rule engine)
- [ ] BullMQ pipeline: crawl job → classify job
- [ ] Test against DVWA

### Phase 3 — Fuzzing Engine (Weeks 6–8)
- [ ] Payload Engine (query MongoDB by attack type)
- [ ] HTTP Sender with rate limiting and concurrency
- [ ] Response Analyzer (ZAP rules + custom heuristics)
- [ ] Mutation Engine
- [ ] Full pipeline: crawl → classify → fuzz → analyze → mutate → re-fuzz

### Phase 4 — Reporting + Dashboard (Weeks 9–10)
- [ ] Vulnerability storage in MongoDB
- [ ] Report Generator (JSON + HTML)
- [ ] Live scan monitor page (SSE)
- [ ] Results and report pages in frontend

### Phase 5 — Polish + Testing (Weeks 11–12)
- [ ] End-to-end test on DVWA, WebGoat, bWAPP
- [ ] Performance tuning
- [ ] Documentation
- [ ] Final Docker Compose production build

---

## 15. What Makes This Original

This is not a copy of any existing tool. The originality lies in:

1. **The Unified Pipeline** — No other free tool combines crawling, context-aware payload selection, adaptive feedback, mutation, and visual reporting in a single system

2. **Parameter Classifier Rule Engine** — The mapping of parameter names to attack type categories is our own logic, built from security research patterns

3. **Adaptive Priority Queue** — Using BullMQ's priority system to re-rank payloads based on response analysis is a novel implementation approach

4. **JavaScript/Node.js Fuzzer** — Nearly all existing fuzzers are Python or C-based. A production-grade fuzzer in the Node.js ecosystem is genuinely new

5. **Modern Full-Stack Dashboard** — The React + real-time SSE dashboard for live fuzzing is far beyond what any free tool currently offers

6. **Zero External Dependencies at Runtime** — No API calls, no cloud, no subscriptions. Everything is local, deterministic, and auditable

---

## Appendix: Folder Structure

```
smartfuzz/
├── docker-compose.yml
├── .env.example
│
├── frontend/                        # React + Tailwind
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── NewScan.jsx
│   │   │   ├── ScanMonitor.jsx
│   │   │   ├── ScanResults.jsx
│   │   │   ├── Reports.jsx
│   │   │   └── PayloadLibrary.jsx
│   │   ├── components/
│   │   ├── hooks/
│   │   └── api/
│   └── Dockerfile
│
├── backend/                         # Node.js + Express
│   ├── src/
│   │   ├── routes/
│   │   │   ├── auth.routes.js
│   │   │   ├── scan.routes.js
│   │   │   ├── vulnerability.routes.js
│   │   │   └── report.routes.js
│   │   ├── controllers/
│   │   ├── middleware/
│   │   │   └── auth.middleware.js   # JWT verification
│   │   ├── models/                  # Mongoose schemas
│   │   │   ├── User.js
│   │   │   ├── Scan.js
│   │   │   ├── Vulnerability.js
│   │   │   ├── Payload.js
│   │   │   └── Report.js
│   │   └── app.js
│   └── Dockerfile
│
├── fuzzer/                          # Fuzzing Engine (Node.js Workers)
│   ├── src/
│   │   ├── workers/
│   │   │   ├── crawlerWorker.js
│   │   │   ├── classifierWorker.js
│   │   │   ├── payloadWorker.js
│   │   │   ├── fuzzWorker.js
│   │   │   ├── analyzerWorker.js
│   │   │   └── mutationWorker.js
│   │   ├── modules/
│   │   │   ├── crawler.js
│   │   │   ├── paramClassifier.js
│   │   │   ├── payloadEngine.js
│   │   │   ├── httpSender.js
│   │   │   ├── responseAnalyzer.js
│   │   │   ├── mutationEngine.js
│   │   │   └── reportGenerator.js
│   │   └── queue/
│   │       └── bullmq.config.js
│   └── Dockerfile
│
├── payloads/                        # Payload source files
│   ├── seclists/
│   ├── payloadsallthethings/
│   ├── fuzzdb/
│   └── seed.js                      # Seeds MongoDB from these files
│
└── docs/
    └── SmartFuzz_Project_Context.md  # This document
```

---

*Document prepared for SmartFuzz Final Year Project — Sinhgad College of Engineering, Pune*
*All tools referenced are open-source and free. Zero external API dependencies.*
