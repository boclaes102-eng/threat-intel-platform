# Threat Intelligence Platform — Backend API

[![CI](https://github.com/boclaes102-eng/threat-intel-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/boclaes102-eng/threat-intel-platform/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/boclaes102-eng/threat-intel-platform/branch/main/graph/badge.svg)](https://codecov.io/gh/boclaes102-eng/threat-intel-platform)

A production-ready backend service that is the shared data layer for a **three-platform security ecosystem**. It monitors registered assets for threats, ingests CVE feeds from NIST NVD, enriches IOC indicators from four sources in parallel, and stores recon sessions from the dashboard so the desktop attack tool can load them.

**Live API:** `https://threat-intel-platform-production-eb1b.up.railway.app` &nbsp;·&nbsp; **Swagger UI:** `/docs`

**Dashboard:** [Online-Cyber-Dashboard](https://github.com/boclaes102-eng/Online-Cyber-dashboard) &nbsp;·&nbsp; **Desktop App:** [CyberSuite Pro](https://github.com/boclaes102-eng/Cybersecurity-software)

---

## What Makes This Special

This backend is not a thin CRUD API. It runs a multi-source enrichment pipeline, a scheduled CVE ingestion worker with exponential backoff and jitter, an asset-to-CVE correlation engine, and a recon session store that bridges a Next.js dashboard to a Python desktop tool. All of this ships as two separate Docker build targets (API + Worker) on a single Railway project, sharing one Postgres and one Redis instance.

The schema is designed for correctness: credentials are never stored in plaintext, foreign keys have explicit `ON DELETE` actions everywhere, the IOC records table uses a TTL-based expiry so stale data is served while workers refresh it in the background, and the `asset_vulnerabilities` join table has a full remediation lifecycle (`open → acknowledged → remediated → false_positive`).

---

## Three-Platform Ecosystem

```
┌──────────────────────────────────────────────────────────────────────┐
│                  CyberOps Dashboard  (Next.js · Vercel)              │
│                                                                       │
│  50+ recon / intel tools                                              │
│  "Save to Workspace" → POST /api/v1/recon-sessions                   │
│  Asset Monitor pages  → /api/v1/assets  alerts  vulnerabilities      │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ HTTPS · X-API-Key
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│              Threat Intel Platform  (this repo · Railway)            │
│                                                                       │
│  Fastify API  (:3001)                                                 │
│  ├─ /api/v1/recon-sessions   ← new: stores dashboard recon output    │
│  ├─ /api/v1/assets           CRUD + immediate IOC scan queue job     │
│  ├─ /api/v1/alerts           read / filter / mark-read               │
│  ├─ /api/v1/vulnerabilities  NVD CVE data + asset correlation        │
│  └─ /api/v1/ioc/:indicator   Redis cache → DB → live 4-source fan    │
│                                                                       │
│  BullMQ Workers                                                       │
│  ├─ cve-feed    every 6h   NVD full sync with exponential backoff    │
│  ├─ ioc-scan    every 1h   AbuseIPDB + VT + OTX per active asset     │
│  └─ asset-scan  on-demand  CPE string correlation → alert creation   │
│                                                                       │
│  PostgreSQL 16  (10 tables, 3 migrations, relational integrity)       │
│  Redis 7        (BullMQ queues + IOC cache + rate limit counters)    │
│  Prometheus + Grafana  (8-panel observability dashboard)             │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ X-API-Key (from config file)
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│              CyberSuite Pro Desktop App  (Python · Windows)          │
│                                                                       │
│  Recon page fetches /api/v1/recon-sessions                            │
│  One click → sets active target → loads into attack tools            │
│  Offline fallback: manual target entry when no internet              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## What Makes This Backend Technically Interesting

### IOC enrichment fan-out with Redis caching
When an indicator (IP, domain, or hash) is looked up, the service checks Redis first (cache hit → instant), then the Postgres `ioc_records` table (recent result → serve stale, queue refresh), then fans out to AbuseIPDB, VirusTotal, and AlienVault OTX in parallel. Results are written back to both Redis and Postgres with a TTL. Expired records are served as a fallback while the background worker refreshes them — the API never blocks waiting for external calls.

### NVD CVE sync with exponential backoff + jitter
The CVE feed worker pages through the full NIST NVD API (100 CVEs per page, ~2,000 pages for a full sync). If NVD rate-limits mid-sync, the worker retries each page up to 4× with exponential backoff and randomised jitter — not a naive sleep loop. Each run is recorded in `feed_syncs` with duration, records processed, and any error message.

### Asset-to-CVE correlation
When a new asset is registered, the asset-scan worker runs a CPE string similarity check against all known CVE `affectedProducts` entries. Matches create entries in the `asset_vulnerabilities` join table and generate alerts for `critical` and `high` severity CVEs. No external call — purely database-side correlation.

### SIEM event ingestion and correlation
The platform acts as the central SIEM backend for the full ecosystem. External sources (currently `thedeepspaceproject.be`) POST events to `/webhook/site-events` authenticated by `X-Webhook-Secret`. Events are stored in `log_events` with a nullable `userId` so anonymous browser-sourced events are fully supported.

A BullMQ correlation worker runs every 60 seconds and evaluates 7 detection rules across all active user contexts (including the `null` context for external sources):

| Rule | Logic | Severity |
|---|---|---|
| Brute Force | 5+ `login_failed` in 10 min | HIGH |
| XSS Attempt | Any `xss_attempt` in 10 min | HIGH |
| SQLi Attempt | Any `sqli_attempt` in 10 min | HIGH |
| Prototype Pollution | Any `prototype_pollution` in 10 min | HIGH |
| IOC Spike | 3+ `ioc_match` in 10 min | HIGH |
| Port Scan | 10+ distinct target ports from same IP in 5 min | MEDIUM |
| Credential Stuffing | 10+ `login_failed` across 3+ target IPs in 5 min | CRITICAL |

Incidents use an upsert pattern — if an open/investigating incident for the same rule exists within 2× the detection window, the event count is incremented rather than creating a duplicate.

### Recon session store (new — added for desktop integration)
The `recon_sessions` table stores the full JSON output of any dashboard tool run (IP lookup, subdomain enumeration, SSL inspection, etc.) alongside a lightweight `summary` object for quick display. The CyberSuite Pro desktop app reads these sessions via the same API key and lets the operator load any target into the attack toolchain with one click.

### Request ID tracing
Every request gets a `X-Request-ID` (accepted from the caller or minted as UUID v4). Every Pino log line includes `reqId`. Every response echoes the header back. A single dashboard request can be traced through the Next.js proxy log, the Fastify request log, the worker job log, and the email send log — all linked by the same ID.

---

## Database Schema

Ten tables across three migrations:

```
users ──< refresh_tokens      (30-day tokens, SHA-256 hashed)
  │   └─< api_keys            (server-to-server keys, SHA-256 hashed)
  │
  ├──< assets ──< asset_vulnerabilities >── vulnerabilities  (NVD data)
  │      │
  │      └──< alerts          (nullable FK — alert survives asset deletion)
  │
  └──< recon_sessions         (tool + target + summary + full results JSON)

ioc_records                   (enriched threat intel per indicator, TTL-based)
feed_syncs                    (job run history: duration, records, errors)
```

**Key design decisions:**
- Passwords use bcrypt (12 rounds). Refresh tokens and API keys are stored as SHA-256 hashes — never recoverable if lost.
- `ioc_records.expires_at` lets the API serve stale data instantly while background workers refresh asynchronously.
- All foreign keys have explicit `ON DELETE` actions — CASCADE or SET NULL — nothing is silently orphaned.
- Cursor-based pagination on all list endpoints — no offset drift on live data.
- `recon_sessions` uses a `recon_tool` PostgreSQL enum (19 values) so the DB enforces valid tool names at the constraint level.

---

## Stack

| Layer | Technology |
|---|---|
| HTTP API | Fastify 4 + TypeScript |
| ORM | Drizzle ORM (typed schema, SQL migrations) |
| Database | PostgreSQL 16 |
| Cache + Queue broker | Redis 7 |
| Job queues | BullMQ |
| Auth | JWT (15 min access) + refresh tokens (30 days) + API keys |
| Validation | Zod throughout (env, request body, query params) |
| Structured logging | Pino (JSON in prod, pretty-printed in dev) |
| Metrics | Prometheus (`prom-client`) + Grafana |
| Containers | Docker multi-stage build (`api` + `worker` targets) |
| CI/CD | GitHub Actions: type check → security audit → unit + integration tests → Codecov |
| Testing | Vitest — unit (mocked externals) + integration (real Postgres + Redis) |
| Docs | Auto-generated Swagger UI at `/docs` |
| Deployment | Railway — API and Worker as separate services sharing Postgres + Redis |

---

## API Reference

All endpoints except `/health`, `/metrics`, `/docs`, and `/api/v1/auth/register|login|refresh` require:
- `Authorization: Bearer <accessToken>`, or
- `X-API-Key: tip_<key>`

Full interactive spec at **`/docs`**.

### Auth
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Create account |
| `POST` | `/api/v1/auth/login` | Login → `{ accessToken, refreshToken }` |
| `POST` | `/api/v1/auth/refresh` | New access token from refresh token |
| `POST` | `/api/v1/auth/logout` | Revoke a refresh token |
| `GET` | `/api/v1/auth/me` | Current user profile |
| `POST` | `/api/v1/auth/api-keys` | Create API key — shown once |
| `DELETE` | `/api/v1/auth/api-keys/:id` | Revoke an API key |

### Recon Sessions *(new)*
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/recon-sessions` | List sessions — filter by `tool`, cursor pagination |
| `GET` | `/api/v1/recon-sessions/:id` | Single session with full results JSON |
| `POST` | `/api/v1/recon-sessions` | Save a tool result `{ tool, target, summary, results, tags }` |
| `PATCH` | `/api/v1/recon-sessions/:id` | Update `tags` or `notes` |
| `DELETE` | `/api/v1/recon-sessions/:id` | Delete session |

**Supported tools:** `ip` `domain` `subdomains` `ssl` `headers` `portscan` `dns` `reverseip` `asn` `whoishistory` `certs` `traceroute` `url` `email` `ioc` `shodan` `tech` `waf` `cors`

### Assets
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/assets` | List — paginated, filterable by `type`, `active` |
| `POST` | `/api/v1/assets` | Register asset — queues IOC scan + CVE correlation immediately |
| `GET` | `/api/v1/assets/:id` | Single asset |
| `PATCH` | `/api/v1/assets/:id` | Update `label`, `tags`, `active` |
| `DELETE` | `/api/v1/assets/:id` | Remove (cascades to alerts + vuln links) |

### Alerts
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/alerts` | List — filter by `severity`, `type`, `unread`, `assetId` |
| `POST` | `/api/v1/alerts/:id/read` | Mark single alert as read |
| `POST` | `/api/v1/alerts/read-all` | Mark all as read |
| `DELETE` | `/api/v1/alerts/:id` | Delete alert |

### Vulnerabilities
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/vulnerabilities` | Global CVE list — filter by `severity`, `search` |
| `GET` | `/api/v1/vulnerabilities?assetId=X` | CVEs linked to a specific asset |
| `GET` | `/api/v1/vulnerabilities/:cveId` | Single CVE with raw NVD data |
| `PATCH` | `/api/v1/assets/:assetId/vulnerabilities/:cveId` | Update remediation status |

### IOC Lookup
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/ioc/:indicator` | Enrich IP, domain, or hash — Redis → DB → live APIs |
| `GET` | `/api/v1/ioc` | List cached IOC records — filter by `verdict` |

### SIEM Events
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/events` | List all events — filter by `category`, `severity`, `source`, `since` (1h/6h/24h/7d). Global view across all users and sources. |
| `POST` | `/api/v1/events` | Ingest an event (authenticated) |
| `POST` | `/webhook/site-events` | Unauthenticated webhook for external sources — requires `X-Webhook-Secret` header |

### SIEM Incidents
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/incidents` | List all incidents — filter by `status`, `severity`. Global view. |
| `PATCH` | `/api/v1/incidents/:id` | Update status (`open` → `investigating` → `resolved`) |

### Pagination

All list endpoints use cursor-based pagination — no offset drift on live data:

```
GET /api/v1/recon-sessions?limit=20&cursor=2025-04-18T10:00:00.000Z&tool=ip
→ { data: [...], nextCursor: "2025-04-17T09:30:00.000Z" | null }
```

---

## Background Workers

| Queue | Schedule | What it does |
|---|---|---|
| `cve-feed` | Every 6 hours | Pages NVD API, upserts CVEs into `vulnerabilities`, records run in `feed_syncs`. Retries with exponential backoff + jitter on rate limits. |
| `ioc-scan` | Every 1 hour | Enriches all active IP/domain assets via AbuseIPDB + VirusTotal + OTX in parallel. Creates `ioc_match` alerts on malicious verdicts. Emails if SMTP configured. |
| `asset-scan` | On asset creation | CPE string correlation against known CVEs. Links matches in `asset_vulnerabilities`. Creates alerts for critical/high CVEs. |
| `event-correlation` | Every 60 seconds | Evaluates 7 detection rules across all event contexts (including external sources with null userId). Creates and deduplicates incidents in the `incidents` table. |

---

## Observability

```bash
docker compose up   # starts Prometheus + Grafana automatically
# Grafana → http://localhost:3002  (admin / admin)
```

8-panel Grafana dashboard (pre-provisioned, loads automatically):

| Panel | Metric |
|---|---|
| Requests / min | `rate(http_requests_total[5m])` |
| Error rate % | 5xx / total |
| Active assets | `active_assets_total` gauge |
| IOC cache hit rate | hits / (hits + misses) |
| Request latency | p50 / p95 / p99 histogram |
| Background job rate | completed vs failed by queue |
| Requests by route | per-endpoint breakdown |
| Open alerts | by severity |

---

## Testing

```bash
npm run test:unit          # unit — no DB/Redis needed, external APIs mocked
npm run test:integration   # integration — requires live Postgres + Redis
npm run test:coverage      # all tests + v8 coverage → coverage/
```

Integration tests use `fastify.inject()` — no real HTTP port — but hit a **live Postgres database** for authentic query behaviour. Tables are truncated `beforeEach` for full isolation. CI runs the full suite with Postgres and Redis as service containers and uploads coverage to Codecov.

---

## Local Setup

### With Docker (recommended)

```bash
cp .env.example .env
# Set JWT_SECRET: openssl rand -base64 48

docker compose up
# API → http://localhost:3001
# Swagger → http://localhost:3001/docs
# Grafana → http://localhost:3002  (admin / admin)
```

### Local development

```bash
npm install
cp .env.example .env
docker compose up postgres redis -d

npm run db:migrate
npm run dev           # API on :3001
npm run dev:worker    # background workers (separate terminal)
```

---

## Railway Deployment

Two services share one Postgres and one Redis add-on:

```
Railway project
├── API service     (Dockerfile target: api)
│   └── runs migrations on startup → starts Fastify on $PORT
├── Worker service  (Dockerfile target: worker)
│   └── BullMQ consumers, no HTTP port
├── Postgres add-on
└── Redis add-on
```

**Required environment variables:**

```
DATABASE_URL   = ${{Postgres.DATABASE_URL}}
REDIS_URL      = ${{Redis.REDIS_URL}}
JWT_SECRET     = <openssl rand -base64 48>
CORS_ORIGIN    = https://your-dashboard.vercel.app
NODE_ENV       = production
```

Optional: `ABUSEIPDB_API_KEY`, `VT_API_KEY`, `NVD_API_KEY`, `OTX_API_KEY`, `SMTP_*` — all features degrade gracefully without them.

---

## Project Structure

```
src/
├── api/
│   ├── plugins/auth.ts          JWT + API key authenticate decorator
│   ├── routes/
│   │   ├── recon-sessions.ts    ← new: dashboard recon output store
│   │   ├── assets.ts
│   │   ├── alerts.ts
│   │   ├── vulnerabilities.ts
│   │   ├── ioc.ts
│   │   └── health.ts
│   └── server.ts                Fastify setup, CORS, rate limit, swagger
├── db/
│   ├── schema/
│   │   ├── recon-sessions.ts    ← new
│   │   ├── assets.ts
│   │   ├── vulnerabilities.ts
│   │   ├── ioc-records.ts
│   │   ├── alerts.ts
│   │   ├── users.ts
│   │   ├── api-keys.ts
│   │   ├── refresh-tokens.ts
│   │   ├── feed-syncs.ts
│   │   └── enums.ts
│   └── index.ts
├── services/
│   ├── ioc-enrichment.ts        fan-out + Redis cache
│   ├── nvd.ts
│   ├── abuseipdb.ts
│   ├── virustotal.ts
│   └── otx.ts
├── workers/
│   ├── cve-feed-worker.ts       NVD sync + exponential backoff
│   ├── ioc-scan-worker.ts       per-asset enrichment + email alerts
│   ├── asset-scan-worker.ts     CVE correlation + email alerts
│   └── queues.ts
├── lib/
│   ├── env.ts                   Zod-validated environment
│   ├── logger.ts                Pino
│   ├── metrics.ts               Prometheus counters, histograms, gauges
│   ├── redis.ts                 ioredis client + cache helpers
│   └── mailer.ts
├── index.ts                     API entry point
└── worker.ts                    Worker process entry point

drizzle/
├── 0000_initial_schema.sql
├── 0001_refresh_and_api_keys.sql
└── 0002_recon_sessions.sql      ← new
```
