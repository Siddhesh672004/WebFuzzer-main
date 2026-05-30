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
elsewhere. Every scan requires an in-app authorization confirmation, which is logged.
Safe practice targets: DVWA, OWASP WebGoat, OWASP Juice Shop, bWAPP.

---

## Architecture

```
frontend (React+Vite) → backend (Express API + SSE) → Redis (BullMQ) → worker (scan engine)
                              ↓                                              ↓
                          MongoDB  ←──────────────────────────────────────────┘
```

- **backend** — owns HTTP: auth, REST, SSE streaming, enqueues scan jobs. Never scans.
- **worker** — separate process running BullMQ workers + the scan engine (crawl/fuzz/analyze).
- **frontend** — static React app.
- **MongoDB** — scans, vulnerabilities, payloads, reports, users.
- **Redis** — BullMQ queues + OTP storage.

This is a monorepo using npm workspaces: `shared`, `backend`, `worker`, `frontend`.

## Tech stack

| Layer    | Tech |
|----------|------|
| Frontend | React 18, Vite 5, Tailwind 3, React Query 5, React Router 6, Recharts, Framer Motion |
| Backend  | Node 20 LTS, Express 4, Mongoose 8, BullMQ 5, ioredis, Nodemailer, jsonwebtoken, zod, pino |
| Data     | MongoDB 7, Redis 7 |
| Testing  | Vitest, supertest, mongodb-memory-server, nock, Testing Library, Playwright |
| Infra    | Docker + Docker Compose |

## Quick start

```bash
# 1. Configure
cp .env.example .env
#   edit .env — set JWT_SECRET; in dev, MAIL_TRANSPORT=ethereal needs no email setup

# 2. Bring up the full stack
docker compose up

# 3. (One-time) seed the payload library into MongoDB
npm run setup:payloads   # clones SecLists/PayloadsAllTheThings/FuzzDB (data only)
npm run seed             # parses wordlists into the `payloads` collection
```

App: http://localhost:5173 · API: http://localhost:4000

### Local development (without Docker for the app code)

```bash
npm install                 # installs all workspaces
docker compose up mongo redis -d
npm run dev:backend         # terminal 1
npm run dev:worker          # terminal 2
npm run dev:frontend        # terminal 3
```

### Testing against vulnerable targets

```bash
docker compose -f docker-compose.yml -f docker-compose.testing.yml --profile testing up
# then set SCAN_ALLOW_PRIVATE=true in .env to scan http://localhost:8080 (DVWA), etc.
```

## Tests

```bash
npm test                    # all workspaces
npm run test:worker         # just the engine (the correctness-critical core)
```

The scan engine is tested against **mocked** HTTP responses (nock / fixtures), never
the live internet — deterministic, safe, and fast.

## Project status

Built phase by phase, test-first. See `IMPLEMENTATION_PLAN.md` for the full blueprint
and `SmartFuzz_PRD.md` for the product spec.

## License

MIT — see `THIRD_PARTY_NOTICES.md` for attribution of all open-source data sources
(SecLists, PayloadsAllTheThings, FuzzDB) and clean-room references (OWASP ZAP, Wapiti,
Nikto). SmartFuzz bundles no third-party scanner code and makes no runtime API calls.
