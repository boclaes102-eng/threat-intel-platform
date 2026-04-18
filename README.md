# Threat Intelligence Platform — Backend API

[![CI](https://github.com/boclaes102-eng/threat-intel-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/boclaes102-eng/threat-intel-platform/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/boclaes102-eng/threat-intel-platform/branch/main/graph/badge.svg)](https://codecov.io/gh/boclaes102-eng/threat-intel-platform)

A production-ready backend service that monitors registered assets for threats, ingests CVE feeds, and enriches IOC data from multiple sources. Designed to pair with [Online-Cyber-Dashboard](./Online-Cyber-dashboard) as a standalone backend service.

**Live API:** `https://threat-intel-platform-production-eb1b.up.railway.app`

---

## Stack

| Layer | Technology |
|---|---|
| HTTP API | [Fastify](https://fastify.dev) + TypeScript |
| Database | PostgreSQL 16 + [Drizzle ORM](https://orm.drizzle.team) (migrations) |
| Cache / Queues | Redis 7 + [BullMQ](https://bullmq.io) |
| Auth | JWT access tokens (15 min) + refresh tokens (30 days) + API keys |
| Observability | Pino structured logs + Prometheus metrics + Grafana dashboards |
| Containers | Docker multi-stage build + docker-compose |
| Deployment | [Railway](https://railway.app) — API + Worker as separate services |
| CI/CD | GitHub Actions: type check → security audit → tests → coverage → Docker build |
| Testing | Vitest — unit tests + integration tests against real Postgres |
| OpenAPI | Auto-generated Swagger UI at `/docs` |

---

## Architecture

```
┌──────────────────────────────────────┐
│  Online-Cyber-Dashboard (Next.js)    │
│  X-API-Key: tip_abc123...            │  ← long-lived API key, no login flow
└─────────────────┬────────────────────┘
                  │ HTTPS
                  ▼
┌─────────────────────────────────────────────────────────────┐
│         Railway — API Service  (Fastify :3001)              │
│  /auth  /assets  /alerts  /vulnerabilities  /ioc  /docs     │
│  Runs DB migrations inline on startup                       │
│  X-Request-ID on every request/response (log correlation)   │
│  Rate limit: 120 req/min per IP via Redis                   │
└─────┬────────────────────────────────────────┬──────────────┘
      │                                        │
      ▼                                        ▼
┌───────────────────┐                ┌──────────────────────┐
│    PostgreSQL     │                │        Redis         │
│  ─────────────── │                │  ────────────────    │
│  users            │◄───────────────│  IOC lookup cache    │
│  refresh_tokens   │                │  BullMQ job queues   │
│  api_keys         │                │  Rate limit counters │
│  assets           │                └──────────────────────┘
│  vulnerabilities  │                          │
│  asset_vulns      │           ┌──────────────┘
│  ioc_records      │           ▼
│  alerts           │  ┌──────────────────────────────────────┐
│  feed_syncs       │  │  Railway — Worker Service (BullMQ)   │
└───────────────────┘  │  ──────────────────────────────────  │
                       │  cve-feed    every 6h  NVD API sync  │
                       │  ioc-scan    every 1h  4-source fan  │
                       │  asset-scan  on-demand CVE correlate │
                       │  → creates alerts + sends email      │
                       └──────────────────────────────────────┘

┌───────────────────────────────────────────────────────────┐
│  Observability (local docker-compose only)                │
│  Prometheus :9090  ←  scrapes /metrics every 15s         │
│  Grafana    :3002  ←  pre-built dashboard (8 panels)     │
└───────────────────────────────────────────────────────────┘
```

---

## Database Schema

Nine tables with full relational integrity across two migrations:

```
users ──< refresh_tokens   (30-day refresh tokens, hashed in DB)
  │   └─< api_keys         (server-to-server keys, SHA-256 hashed)
  │
  └──< assets ──< asset_vulnerabilities >── vulnerabilities
        │                                        (NVD CVE data)
        └──< alerts  (nullable FK — alert survives asset deletion)

ioc_records  (enriched threat intel per indicator, TTL-based)
feed_syncs   (job run history: duration, records processed, errors)
```

**Key design decisions:**
- Refresh tokens and API keys are never stored in plaintext — refresh tokens use SHA-256, passwords use bcrypt (12 rounds)
- `asset_vulnerabilities` is a proper join table with a `status` enum (`open` → `acknowledged` → `remediated`)
- `ioc_records.expires_at` lets the API serve stale data as a fallback while background workers refresh
- All foreign keys have explicit `ON DELETE` actions (CASCADE or SET NULL)

---

## Quick Start

### With Docker (recommended)

```bash
cp .env.example .env
# Edit .env — set JWT_SECRET at minimum (openssl rand -base64 48)

docker compose up
```

| Service | URL | Credentials |
|---|---|---|
| API | `http://localhost:3001` | — |
| Swagger UI | `http://localhost:3001/docs` | — |
| Prometheus | `http://localhost:9090` | — |
| Grafana | `http://localhost:3002` | admin / admin |

### Local development

```bash
npm install
cp .env.example .env

# Start infrastructure only
docker compose up postgres redis -d

npm run db:migrate        # run both migrations
npm run dev               # API on :3001
npm run dev:worker        # background workers (separate terminal)
```

### Useful scripts

```bash
npm run db:generate       # regenerate Drizzle migration files from schema
npm run db:studio         # open Drizzle Studio (visual DB browser)
npm run lint              # TypeScript type check (no emit)
```

---

## Auth & Security

### Token flow (browser / mobile clients)

```
POST /api/v1/auth/login
  → { accessToken (JWT, 15 min), refreshToken (opaque, 30 days), expiresIn: 900 }

# When access token expires, silently renew:
POST /api/v1/auth/refresh  { refreshToken: "..." }
  → { accessToken (new JWT, 15 min), expiresIn: 900 }

# On logout, invalidate the refresh token:
POST /api/v1/auth/logout   { refreshToken: "..." }
  → { success: true }
```

Refresh tokens are random 128-char hex strings stored as SHA-256 hashes. Revoking one does not invalidate others (supports multi-device).

### API key flow (server-to-server)

The dashboard calls this API without a user login flow. Use an API key instead:

```bash
# One-time setup: create a key (requires a JWT from your own login)
curl -X POST http://localhost:3001/api/v1/auth/api-keys \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"name": "online-cyber-dashboard"}'
# → { "data": { "key": "tip_abc123...", "id": "...", "name": "..." } }
#   The key is shown exactly once. Store it securely.
```

Keys are prefixed `tip_` and stored as SHA-256 hashes — not recoverable if lost. Revoke with `DELETE /api/v1/auth/api-keys/:id`.

### Request correlation

Every request gets a `X-Request-ID` (accepted from caller or minted as UUID). Every log line includes `reqId`. Every response echoes `X-Request-ID` back, so you can trace a dashboard request through API logs and worker logs.

---

## API Reference

All endpoints except `/health`, `/metrics`, `/docs`, and `/api/v1/auth/register|login|refresh` require one of:
- `Authorization: Bearer <accessToken>`
- `X-API-Key: tip_<key>`

The full interactive spec is at **`http://localhost:3001/docs`**.

### Auth
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Create account → `{ accessToken, refreshToken, user }` |
| `POST` | `/api/v1/auth/login` | Login → `{ accessToken, refreshToken, expiresIn: 900, user }` |
| `POST` | `/api/v1/auth/refresh` | New access token from refresh token |
| `POST` | `/api/v1/auth/logout` | Revoke a refresh token |
| `GET` | `/api/v1/auth/me` | Current user profile |
| `GET` | `/api/v1/auth/api-keys` | List your API keys (hashes never shown) |
| `POST` | `/api/v1/auth/api-keys` | Create API key — `{ "name": "..." }` → key shown once |
| `DELETE` | `/api/v1/auth/api-keys/:id` | Revoke an API key |

### Assets
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/assets` | List assets — paginated, filterable by `type`, `active` |
| `POST` | `/api/v1/assets` | Register asset — immediately queues IOC scan + CVE correlation |
| `GET` | `/api/v1/assets/:id` | Single asset |
| `PATCH` | `/api/v1/assets/:id` | Update `label`, `tags`, `active` |
| `DELETE` | `/api/v1/assets/:id` | Remove asset (cascades to alerts + vuln links) |

**Asset types:** `ip`, `domain`, `cidr`, `url`

### Alerts
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/alerts` | List alerts — filter by `severity`, `type`, `unread`, `assetId` |
| `POST` | `/api/v1/alerts/:id/read` | Mark single alert as read |
| `POST` | `/api/v1/alerts/read-all` | Mark all alerts as read |
| `DELETE` | `/api/v1/alerts/:id` | Delete alert |

**Alert types:** `vulnerability`, `ioc_match`, `scan_complete`, `feed_update`

### Vulnerabilities
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/vulnerabilities` | Global CVE list — filter by `severity`, `search` (CVE ID) |
| `GET` | `/api/v1/vulnerabilities?assetId=X` | CVEs linked to a specific asset, with per-asset `status` |
| `GET` | `/api/v1/vulnerabilities/:cveId` | Single CVE detail with raw NVD data |
| `PATCH` | `/api/v1/assets/:assetId/vulnerabilities/:cveId` | Update remediation status |

**Vuln statuses:** `open` → `acknowledged` → `remediated` → `false_positive`

### IOC Lookup
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/ioc/:indicator` | Enrich IP, domain, or hash — checks Redis → DB → live APIs |
| `GET` | `/api/v1/ioc` | List all cached IOC records — filter by `verdict` |

**Verdicts:** `malicious`, `suspicious`, `clean`, `unknown`

### System
| Endpoint | Description |
|---|---|
| `GET /health` | Always returns `{ status: "ok" }` — used by Railway and load balancers |
| `GET /metrics` | Prometheus scrape endpoint |
| `GET /docs` | Swagger UI — full interactive OpenAPI 3.0 spec |

### Pagination

All list endpoints use cursor-based pagination (no offset drift on live data):

```
GET /api/v1/alerts?limit=20&cursor=2024-01-15T10:00:00.000Z&severity=high&unread=true
→ {
    data: [...],
    nextCursor: "2024-01-14T09:30:00.000Z"   // null if no more pages
  }
```

Pass `nextCursor` as `cursor` in your next request to get the next page.

---

## Background Workers

Workers run as a separate process (`npm run dev:worker`) consuming three BullMQ queues backed by Redis.

| Queue | Schedule | What it does |
|---|---|---|
| `cve-feed` | Every 6 hours | Pages through NVD API, upserts CVEs into `vulnerabilities` table, records run stats in `feed_syncs`. Retries each page up to 4× with exponential backoff + jitter if NVD rate-limits mid-sync. |
| `ioc-scan` | Every hour | Enriches all active IP/domain assets via AbuseIPDB + VirusTotal + AlienVault OTX in parallel. Inserts/updates `ioc_records`. Creates `ioc_match` alert on malicious/suspicious verdict. Sends email if SMTP configured. |
| `asset-scan` | On asset creation | Correlates the asset value against CPE strings in all known CVEs. Links matches in `asset_vulnerabilities`. Creates `vulnerability` alert for critical/high CVEs. Sends email if SMTP configured. |

All workers track job duration in Prometheus (`job_duration_seconds`) and increment `jobs_total{status="completed|failed"}` for the Grafana dashboard.

---

## Observability

### Prometheus + Grafana

```bash
docker compose up   # starts Prometheus + Grafana automatically
```

Open Grafana at `http://localhost:3002` (admin / admin). The **Threat Intelligence Platform** dashboard loads automatically with 8 panels:

| Panel | Metric |
|---|---|
| Requests / min | `rate(http_requests_total[5m])` |
| Error rate % | 5xx / total requests |
| Active assets | `active_assets_total` gauge |
| Cache hit rate | hits / (hits + misses) |
| Request latency | p50 / p95 / p99 histogram |
| Background job rate | completed vs failed by queue |
| Requests by route | breakdown per endpoint |
| Open alerts | by severity (critical / high / medium / low) |

### Structured logging

Every log line is structured JSON (Pino) with `reqId`, `service`, and `env` fields. In development, `pino-pretty` formats it for readability:

```
10:24:31 INFO  reqId=a3f2... method=POST url=/api/v1/assets status=201 ms=12.4
10:24:31 WARN  reqId=a3f2... indicator=1.2.3.4 verdict=malicious score=87  IOC threat detected
```

---

## Testing

```bash
npm run test:unit          # unit tests — no DB or Redis needed (external APIs are mocked)
npm run test:integration   # integration tests — requires Postgres + Redis running
npm run test:coverage      # all tests with v8 coverage report → coverage/
```

Integration tests use `fastify.inject()` — no real HTTP port, no network — but hit a **live Postgres database** for real query behaviour. The test setup truncates all tables `beforeEach` for isolation.

CI runs the full suite with Postgres and Redis as service containers, uploads results to Codecov, and fails on `npm audit --audit-level=high` findings.

---

## Railway Deployment

The API and Worker run as two separate Railway services sharing the same Postgres and Redis add-ons.

### Services

| Service | Config file | Start command | Notes |
|---|---|---|---|
| API | `railway.toml` | `node dist/index.js` | Runs DB migrations inline on every deploy, then starts Fastify |
| Worker | `railway.worker.toml` | `node dist/worker.js` | BullMQ consumers + recurring job scheduler |

### How deploys work

1. Railway builds the `api` Docker stage from `Dockerfile`
2. On startup, `index.ts` runs all pending Drizzle migrations before binding the HTTP port — no separate migration step needed
3. The `health` endpoint at `/health` returns 200 immediately once the server is up

### Architecture on Railway

```
Railway project
├── API service          (Dockerfile target: api)
│   └── auto-runs migrations → starts Fastify on $PORT
├── Worker service       (Dockerfile target: worker)
│   └── consumes BullMQ queues, no HTTP port
├── Postgres add-on      (shared between both services)
└── Redis add-on         (shared between both services)
```

### Required environment variables on Railway

Set these in each service's variable panel (use Railway's variable references where possible):

```
DATABASE_URL   = ${{Postgres.DATABASE_URL}}
REDIS_URL      = ${{Redis.REDIS_URL}}
JWT_SECRET     = <generate: openssl rand -base64 48>
CORS_ORIGIN    = https://your-dashboard-domain.com
NODE_ENV       = production
```

External API keys (`ABUSEIPDB_API_KEY`, `VT_API_KEY`, `NVD_API_KEY`, `OTX_API_KEY`) are optional — all features degrade gracefully without them.

---

## Dashboard Integration

The dashboard calls this API as a backend service using a long-lived API key — no user login flow, no Clerk tokens, no session management needed on the backend side.

**Setup (one time):**

```bash
# 1. Register your own account on the backend
curl -X POST http://localhost:3001/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yoursite.com","password":"strongpassword"}'

# 2. Create a named API key for the dashboard
curl -X POST http://localhost:3001/api/v1/auth/api-keys \
  -H "Authorization: Bearer <accessToken from step 1>" \
  -H "Content-Type: application/json" \
  -d '{"name":"online-cyber-dashboard"}'
# → { "data": { "key": "tip_abc123...", ... } }
```

**In `Online-Cyber-Dashboard/.env.local`:**

```env
THREAT_INTEL_API_URL=http://localhost:3001
THREAT_INTEL_API_KEY=tip_abc123...
```

**Calling from a Next.js route handler:**

```typescript
// app/api/threat/assets/route.ts
export async function GET() {
  const res = await fetch(`${process.env.THREAT_INTEL_API_URL}/api/v1/assets`, {
    headers: { 'X-API-Key': process.env.THREAT_INTEL_API_KEY! },
    next: { revalidate: 60 },
  });
  const { data } = await res.json();
  return Response.json({ data });
}

// app/api/threat/alerts/route.ts
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const url = new URL(`${process.env.THREAT_INTEL_API_URL}/api/v1/alerts`);
  url.searchParams.set('unread', 'true');
  url.searchParams.set('limit', searchParams.get('limit') ?? '20');

  const res = await fetch(url.toString(), {
    headers: { 'X-API-Key': process.env.THREAT_INTEL_API_KEY! },
  });
  return Response.json(await res.json());
}
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in required values.

### Required

| Variable | Description |
|---|---|
| `DATABASE_URL` | Postgres connection string |
| `JWT_SECRET` | Min 32 characters — generate with `openssl rand -base64 48` |

### Auth

| Variable | Default | Description |
|---|---|---|
| `ACCESS_TOKEN_EXPIRY` | `15m` | JWT access token lifetime |
| `REFRESH_TOKEN_EXPIRY_DAYS` | `30` | Refresh token lifetime in days |

### Infrastructure

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `DB_POOL_MAX` | `20` | Max Postgres connection pool size |
| `PORT` | `3001` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP bind address |
| `CORS_ORIGIN` | `http://localhost:3000` | Comma-separated allowed origins |
| `LOG_LEVEL` | `info` | `trace` `debug` `info` `warn` `error` `fatal` |

### External APIs (all optional — features degrade gracefully)

| Variable | Used for |
|---|---|
| `ABUSEIPDB_API_KEY` | IP reputation scoring in IOC enrichment |
| `VT_API_KEY` | VirusTotal IP and domain analysis |
| `NVD_API_KEY` | Higher NVD rate limit (50 req/30s vs 5 req/30s) |
| `OTX_API_KEY` | AlienVault OTX threat pulse lookup |

### Email alerts (optional)

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | — | SMTP server host — leave blank to disable email |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASS` | — | SMTP password |
| `SMTP_FROM` | `alerts@threat-intel.local` | Sender address |

### Observability

| Variable | Default | Description |
|---|---|---|
| `GRAFANA_PASSWORD` | `admin` | Grafana admin password (docker-compose only) |

---

## Project Structure

```
src/
├── api/
│   ├── plugins/
│   │   └── auth.ts          # JWT + API key authenticate decorator
│   ├── routes/
│   │   ├── auth.ts          # register / login / refresh / logout / api-keys
│   │   ├── assets.ts        # CRUD + pagination
│   │   ├── alerts.ts        # list / read / delete
│   │   ├── vulnerabilities.ts
│   │   ├── ioc.ts
│   │   └── health.ts        # /health + /metrics
│   └── server.ts            # Fastify setup, CORS, rate limit, swagger, hooks
├── db/
│   ├── schema/              # Drizzle table definitions (9 tables)
│   ├── index.ts             # postgres.js connection + Drizzle instance
│   └── migrate.ts           # migration runner
├── lib/
│   ├── env.ts               # Zod-validated environment
│   ├── logger.ts            # Pino structured logger
│   ├── mailer.ts            # Nodemailer — skips if SMTP_HOST unset
│   ├── metrics.ts           # Prometheus counters, histograms, gauges
│   └── redis.ts             # ioredis client + cache helpers
├── services/
│   ├── nvd.ts               # NVD CVE API client
│   ├── abuseipdb.ts
│   ├── virustotal.ts
│   ├── otx.ts
│   └── ioc-enrichment.ts    # fan-out across all sources, Redis cache
├── workers/
│   ├── queues.ts            # BullMQ Queue definitions + recurring job setup
│   ├── cve-feed-worker.ts   # NVD sync with exponential backoff
│   ├── ioc-scan-worker.ts   # per-asset IOC enrichment + email alerts
│   └── asset-scan-worker.ts # CVE correlation + email alerts
├── index.ts                 # API server entry point
└── worker.ts                # Worker process entry point

drizzle/
├── 0000_initial_schema.sql
└── 0001_refresh_and_api_keys.sql

grafana/
├── dashboards/threat-intel.json
└── provisioning/
    ├── datasources/prometheus.yml
    └── dashboards/dashboard.yml

.github/workflows/ci.yml     # lint → audit → test → coverage → docker build
prometheus.yml               # scrape config
```
