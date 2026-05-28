# IOC Scanner

![IOC Scanner Poster](poster.png)

# IoC Scanner

A self-hosted threat intelligence REST API that accepts IP addresses, URLs,
domains, file hashes, and file uploads and runs them concurrently against eight
intelligence sources — returning a unified verdict, confidence score, and
enrichment data. All results are cached in PostgreSQL so repeated lookups never
hit external APIs.

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Who It Is For](#who-it-is-for)
- [Intelligence Sources](#intelligence-sources)
- [How the Pipeline Works](#how-the-pipeline-works)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Database Migrations](#database-migrations)
- [Running with Docker](#running-with-docker)
- [API Reference](#api-reference)
- [Architecture Decisions](#architecture-decisions)
- [Development](#development)
- [Build Phases](#build-phases)
- [Out of Scope](#out-of-scope)

---

## Why This Exists

Security analysts and IT teams frequently encounter suspicious indicators during
incident response, phishing investigations, or routine log review. Checking each
IOC manually across VirusTotal, AbuseIPDB, Shodan, and sandbox platforms is
slow, inconsistent, and burns through free-tier API quotas inefficiently.

This scanner automates that workflow — one API call returns a correlated verdict
from all sources in parallel, preserving quota by caching results and gating
expensive sandbox calls behind a fast triage step.

---

## Who It Is For

| User | Use Case |
|---|---|
| Security Analyst | Rapid IOC triage during incident response |
| SOC Team | Automating enrichment on SIEM alerts |
| IT Administrator | Vetting suspicious IPs from firewall or DNS logs |
| Threat Intelligence Team | Bulk IOC validation in CTI pipelines |

---

## Intelligence Sources

| Source | IOC Types Supported | Scan Mode |
|---|---|---|
| ClamAV | File | Local AV scan — no quota, no network |
| VirusTotal | IP, URL, Domain, Hash | DB Lookup |
| AbuseIPDB | IP | DB Lookup |
| URLhaus | URL, Domain | DB Lookup |
| PhishTank | URL | DB Lookup |
| Shodan | IP | DB Lookup + Infrastructure Enrichment |
| ANY.RUN | URL, File | Sandbox Detonation |
| Hybrid Analysis | IP, URL, Domain, Hash, File | DB Lookup + Sandbox |

---

## How the Pipeline Works

### Single IOC — `/scan/full`

```
Incoming IOC
     │
     ▼
PostgreSQL cache hit? ──Yes──► Return cached result immediately
     │
     No
     │
     ├─ File IOC ──► ClamAV (local, free, instant)
     │                    │
     │               FOUND ──► malicious — skip sandbox, quota preserved
     │                    │
     │                    OK ──► VirusTotal hash lookup
     │                               │
     │                         sandbox=true ──► ANY.RUN + Hybrid Analysis
     │
     ├─ IP IOC ────► AbuseIPDB + VirusTotal (concurrent)
     │                    │
     │               flagged? ──► Shodan enrichment (gated — free tier)
     │
     └─ URL/Domain ► VirusTotal + URLhaus + PhishTank + ANY.RUN + HA (concurrent)
          │
          ▼
     Normalize all results → CTIResult
          │
          ▼
     compute_verdict() → weighted aggregation
          │
          ▼
     Upsert to PostgreSQL → return response
```

### Batch IOC — `/scan/batch`

```
POST /scan/batch  {iocs: [...up to 100...]}
     │
     ▼
Returns 202 immediately with batch_id
     │
     ▼ (background thread)
asyncio.Semaphore(5) — max 5 IOCs scanned simultaneously
     │
     ├─ IOC 1 ──► full pipeline → write to DB → update progress
     ├─ IOC 2 ──► full pipeline → write to DB → update progress
     └─ IOC N ──► ...
     │
     ▼
GET /batch/<batch_id> → poll until status == "done"
```

---

## Features

### Multi-Source Concurrent Scanning

`POST /scan/full` fans out to all applicable sources simultaneously using
`asyncio.gather()`. No source waits for another. The response includes
individual per-source results and a single aggregated final verdict.

### Unified Verdict Engine

All scanner results are normalized into a shared `CTIResult` dataclass and
passed to `compute_verdict()`, which produces a single verdict (`clean`,
`suspicious`, `malicious`, or `unknown`), a confidence score from 0–100, a
list of contributing sources, and a list of sources that errored out so the
analyst knows exactly what coverage was available.

Sandbox sources (ANY.RUN, Hybrid Analysis) carry higher weight than passive DB
lookups. ClamAV carries maximum confidence — a `FOUND` result is treated as
certain.

### ClamAV Local File Scanning

For file IOCs, ClamAV always runs first. It is local, free, and instant — no
API key, no network call, no quota cost. A positive ClamAV hit means the file
is already a known malware signature; sandbox detonation is skipped entirely,
preserving your ANY.RUN and Hybrid Analysis quota for genuinely unknown samples.

### Batch IOC Scanning

`POST /scan/batch` accepts up to 100 IOCs in a single request, each with its
own type. The endpoint returns a `batch_id` immediately (`202 Accepted`).
Scanning runs in a background thread, gated by a semaphore that caps concurrent
scans at 5 to protect free-tier rate limits. Results are written to PostgreSQL
after each IOC completes, so partial results are available mid-batch via
`GET /batch/<batch_id>`.

### Smart Quota Management

**Shodan gating:** Shodan is only called when `ioc_type` is `ip` AND at least
one other source already flagged it as suspicious or malicious. Clean IPs never
consume a Shodan free-tier call (100/month limit).

**PostgreSQL caching:** Every result is upserted after the first scan, keyed on
`(ioc, source)`. Subsequent lookups of the same IOC are served from the
database instantly. A forced rescan is triggered by `DELETE /results/<ioc>`.

**ClamAV gate:** Known malware caught by ClamAV never reaches ANY.RUN or
Hybrid Analysis, making sandbox quota last significantly longer in practice.

**Sandbox escalation:** ANY.RUN and Hybrid Analysis default to their fast DB
lookup path. Full sandbox detonation is opt-in via `"sandbox": true`.

### Cache-First Architecture

Every route checks PostgreSQL before touching any external API. The cache is
never stale by accident — eviction is always explicit via the `DELETE` endpoint.

### IOC Type Auto-Detection *(planned)*

When `"type"` is omitted, the scanner infers it from the value:

| Pattern | Detected As |
|---|---|
| Valid IPv4 / IPv6 | `ip` |
| MD5 / SHA1 / SHA256 hex string | `hash` |
| `http://` or `https://` prefix | `url` |
| Bare hostname with TLD | `domain` |
| Local file path | `file` |

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Python | 3.12 |
| Package Manager | uv | latest |
| Web Framework | Flask | 3.x |
| Async I/O | asyncio + aiohttp | 3.x |
| AV Engine | ClamAV + pyclamd | 0.4.x |
| Database | PostgreSQL | 16 |
| DB Driver | psycopg2 | 2.9 |
| Migrations | Alembic | 1.x |
| Config | python-dotenv + dataclass | 1.x |
| Testing | pytest | 8.x |
| Linting | ruff | 0.4+ |

---

## Project Structure

```
iocscanner/
├── pyproject.toml
├── .env                        # never committed — see .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
│
├── app.py                      # Flask app + all routes
├── config.py                   # Env var loading → frozen Config dataclass
├── models.py                   # CTIResult dataclass + compute_verdict()
├── db.py                       # PostgreSQL connection + upsert helpers
├── validators.py               # Request input validation
├── cache.py                    # Cache read/write logic
├── batch.py                    # Batch job orchestration + semaphore logic
├── logger.py                   # Structured JSON logging
│
├── migrations/                 # Alembic migrations
│   ├── env.py                  # reads DATABASE_URL from .env
│   ├── script.py.mako
│   ├── alembic.ini             # sqlalchemy.url left blank — set via env.py
│   └── versions/
│       ├── 0001_create_cti_results.py
│       ├── 0002_create_shodan_usage.py
│       ├── 0003_create_batch_jobs.py
│       └── 0004_create_clamav_results.py
│
├── clamav_client.py            # Local AV scan via pyclamd
├── virustotal_client.py
├── abuseipdb_client.py
├── urlhaus_client.py
├── phishtank_client.py
├── shodan_client.py            # Gated — IP only, flagged IOCs only
├── anyrun_client.py            # Sandbox — submit → poll → parse
├── hybridanalysis_client.py    # DB lookup fast path + optional sandbox
│
└── tests/
    ├── test_models.py
    ├── test_clamav.py
    ├── test_virustotal.py
    ├── test_abuseipdb.py
    ├── test_urlhaus.py
    ├── test_phishtank.py
    ├── test_shodan.py
    ├── test_anyrun.py
    └── test_hybridanalysis.py
```

---

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- PostgreSQL 16
- ClamAV with `clamd` daemon running (for file scanning)

### Install

```bash
# Clone and enter the project
git clone https://github.com/yourorg/iocscanner.git
cd iocscanner

# Pin Python version and install all dependencies
uv python pin 3.12
uv sync
```

### Configure

```bash
cp .env.example .env
# Fill in your API keys — see Environment Variables section below
```

### Run migrations

```bash
uv run alembic upgrade head
```

### Start the server

```bash
uv run flask --app app run --debug
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in all values. No credentials are ever
hardcoded — all secrets are read exclusively from this file at startup.

```env
# ── API Keys ────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
ANYRUN_API_KEY=
HYBRIDANALYSIS_API_KEY=
PHISHTANK_API_KEY=

# ── PostgreSQL ───────────────────────────────────────────────────────────────
# The official postgres Docker image reads POSTGRES_* automatically.
# DATABASE_URL is assembled from them for SQLAlchemy / Alembic.
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=ioc_scanner
POSTGRES_USER=
POSTGRES_PASSWORD=
DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}

# ── ClamAV ───────────────────────────────────────────────────────────────────
# Unix socket (default, preferred for local installs)
CLAMD_SOCKET=/var/run/clamd.scan/clamd.sock
CLAMD_USE_TCP=false

# TCP (use when clamd runs in a separate Docker container)
# CLAMD_USE_TCP=true
# CLAMD_HOST=clamav
# CLAMD_PORT=3310

# ── Flask ────────────────────────────────────────────────────────────────────
FLASK_ENV=development
FLASK_DEBUG=1
```

`config.py` loads all variables into a frozen `@dataclass` at startup and
raises a clear `EnvironmentError` listing every missing key before the server
accepts any traffic.

---

## Database Migrations

Migrations are managed with Alembic. The `sqlalchemy.url` in `alembic.ini` is
intentionally blank — `migrations/env.py` reads `DATABASE_URL` from `.env` at
runtime so credentials are never in version control.

```bash
# Apply all pending migrations (run once after clone, again after pulling new migrations)
uv run alembic upgrade head

# Roll back one migration
uv run alembic downgrade -1

# Auto-generate a migration from a schema change
uv run alembic revision --autogenerate -m "add_tags_column"

# Check current revision
uv run alembic current

# Full history
uv run alembic history --verbose
```

### Migration Inventory

| File | Creates |
|---|---|
| `0001_create_cti_results.py` | Main results cache table with indexes |
| `0002_create_shodan_usage.py` | Monthly quota tracker for Shodan free tier |
| `0003_create_batch_jobs.py` | Async batch job state and progress tracking |
| `0004_create_clamav_results.py` | Adds `av_signature` column to `cti_results` |

---

## Running with Docker

The full stack (app + PostgreSQL + ClamAV) is orchestrated with Docker Compose.
Alembic migrations run automatically on app container startup before Flask
begins accepting traffic. ClamAV downloads its virus definitions on first start
— allow ~2 minutes before scanning files.

```yaml
# docker-compose.yml
services:
  app:
    build: .
    ports: ["5000:5000"]
    env_file: .env
    depends_on: [db, clamav]
    environment:
      CLAMD_USE_TCP: "true"
      CLAMD_HOST: "clamav"
      CLAMD_PORT: "3310"
    command: >
      sh -c "uv run alembic upgrade head &&
             uv run flask --app app run --host 0.0.0.0"

  db:
    image: postgres:16
    env_file: .env
    volumes:
      - pgdata:/var/lib/postgresql/data

  clamav:
    image: clamav/clamav:stable
    ports: ["3310:3310"]
    volumes:
      - clamav_data:/var/lib/clamav

volumes:
  pgdata:
  clamav_data:
```

```bash
docker compose up --build
```

---

## API Reference

### Endpoints

| Method | Route | Description |
|---|---|---|
| `GET` | `/health` | Liveness check + DB connectivity + Shodan quota |
| `GET` | `/sources` | Lists all sources, their status, and supported IOC types |
| `GET` | `/metrics` | Scan counts, verdict breakdown, cache hit rate, error rates |
| `POST` | `/scan/single` | Scan one IOC against one specific source |
| `POST` | `/scan/full` | Scan one IOC against all sources concurrently |
| `POST` | `/scan/batch` | Submit up to 100 IOCs for async background scanning |
| `GET` | `/batch/<batch_id>` | Poll batch job progress and results |
| `GET` | `/results/<ioc>` | Retrieve cached results for an IOC |
| `DELETE` | `/results/<ioc>` | Evict an IOC from cache to force a fresh scan |

---

### `POST /scan/full`

Scan a single IOC against all applicable sources concurrently.

```bash
curl -X POST http://localhost:5000/scan/full \
  -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.47", "type": "ip", "sandbox": false}'
```

```json
// Response
{
  "verdict": {
    "verdict": "malicious",
    "confidence": 87,
    "contributing": ["virustotal", "abuseipdb"],
    "errors": []
  },
  "results": [
    {
      "source": "virustotal",
      "ioc": "185.220.101.47",
      "ioc_type": "ip",
      "verdict": "malicious",
      "malicious": true,
      "confidence": 91,
      "tags": ["tor-exit-node"],
      "report_url": "https://virustotal.com/gui/ip-address/185.220.101.47",
      "error": null
    },
    {
      "source": "shodan",
      "verdict": "unknown",
      "tags": ["tor", "open-proxy"],
      "enrichment": {
        "ports": [9001, 9030, 443],
        "asn": "AS24940",
        "org": "Hetzner Online GmbH",
        "country": "DE"
      },
      "error": null
    }
  ]
}
```

---

### `POST /scan/single`

Scan one IOC against one named source.

```bash
curl -X POST http://localhost:5000/scan/single \
  -H "Content-Type: application/json" \
  -d '{"ioc": "http://evil.example.com", "type": "url", "source": "urlhaus"}'
```

---

### `POST /scan/batch`

Submit up to 100 IOCs. Returns immediately — scan runs in the background.

```bash
curl -X POST http://localhost:5000/scan/batch \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      {"ioc": "185.220.101.47",                    "type": "ip"},
      {"ioc": "http://evil.example.com",            "type": "url"},
      {"ioc": "d41d8cd98f00b204e9800998ecf8427e",  "type": "hash"}
    ],
    "sandbox": false
  }'
```

```json
// Response — 202 Accepted
{
  "batch_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "total": 3,
  "status": "pending",
  "poll_url": "/batch/f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

---

### `GET /batch/<batch_id>`

Poll until `status` is `done` or `failed`.

```json
// While running
{
  "batch_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "running",
  "total": 3,
  "completed": 1,
  "failed": 0,
  "results": [...],
  "created_at": "2026-05-22T10:00:00Z",
  "finished_at": null
}

// When done
{
  "batch_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "done",
  "total": 3,
  "completed": 3,
  "failed": 0,
  "results": [...],
  "created_at": "2026-05-22T10:00:00Z",
  "finished_at": "2026-05-22T10:00:47Z"
}
```

---

### `GET /health`

```json
{
  "status": "ok",
  "db": "connected",
  "shodan_quota_used": 42,
  "shodan_quota_limit": 100
}
```

### `GET /metrics`

```json
{
  "total_scans": 1042,
  "verdicts": {"malicious": 312, "suspicious": 88, "clean": 601, "unknown": 41},
  "errors_by_source": {"anyrun": 3, "phishtank": 0},
  "cache_hit_rate": "74%"
}
```

### Error Responses

All errors are structured JSON — never plain text or HTML.

```json
{"error": "ioc is required",                  "code": "MISSING_FIELD",  "status": 400}
{"error": "Batch size exceeds limit of 100",  "code": "BATCH_TOO_LARGE","status": 422}
{"error": "Batch job not found",              "code": "NOT_FOUND",      "status": 404}
```

A single source failing never blocks a `/scan/full` or `/scan/batch` response.
Source errors appear in `result.error` and in the top-level `verdict.errors` list.

---

## Architecture Decisions

### Why `asyncio.to_thread()` for ClamAV?

`pyclamd` is a synchronous library. Wrapping it in `asyncio.to_thread()` means
it runs in a thread pool without blocking the event loop, keeping the async
execution model consistent across all scanners.

### Why `asyncio.Semaphore` in batch?

A semaphore caps concurrent IOC scans at 5 regardless of batch size. Without it,
100 simultaneous IOCs would immediately exhaust free-tier rate limits on every
source. The cap is tunable via `BATCH_CONCURRENCY` in `batch.py`.

### Why is Shodan gated?

Shodan's free tier gives 100 API calls per month. Calling it on every IP would
burn the quota in hours. The gate (only call Shodan when another source already
flagged the IP) reserves calls for IPs that actually need infrastructure
enrichment.

### Why weighted verdicts?

Not all sources are equally reliable. A sandbox that actually detonated the
sample (ANY.RUN, Hybrid Analysis) is more authoritative than a passive DB lookup.
Weights ensure a sandbox hit carries more influence over the final verdict than a
single AbuseIPDB report.

### Why `alembic.ini` has a blank `sqlalchemy.url`?

To ensure database credentials are never written to disk in version control.
`migrations/env.py` reads `DATABASE_URL` from `.env` at runtime. Any migration
run without a configured `.env` fails with a clear `EnvironmentError`.

---

## Development

```bash
# Run all tests
uv run pytest

# Run a specific test file
uv run pytest tests/test_clamav.py -v

# Lint
uv run ruff check .

# Add a new dependency
uv add <package>

# Add a dev dependency
uv add --dev <package>

# Generate a new Alembic migration
uv run alembic revision --autogenerate -m "describe_change"

# Apply migrations
uv run alembic upgrade head
```

### ClamAV — Local Development (Fedora / RHEL)

```bash
sudo dnf install clamav clamav-daemon clamav-update
sudo freshclam
sudo systemctl enable --now clamd@scan
```

---

## Build Phases

| Phase | Goal | Timeline |
|---|---|---|
| 1 — Scaffolding | Project skeleton, config layer, DB connection | Day 1 |
| 2 — Data Layer | `CTIResult` dataclass, `compute_verdict()`, normalizers | Day 1–2 |
| 3 — Scanner Modules | All 8 scanner clients built and tested independently | Day 2–5 |
| 4 — Flask API | All routes, batch orchestration, caching, Shodan gating | Day 5–7 |
| 5 — Hardening | Timeouts, quota tracking, structured logging, Docker | Day 7–9 |

### Scanner Build Order (Phase 3)

| Order | Module | Reason |
|---|---|---|
| 1 | `clamav_client.py` | No API key needed — validate setup immediately |
| 2 | `virustotal_client.py` | Most feature-complete free tier, good baseline |
| 3 | `abuseipdb_client.py` | Simple IP lookup — fast to implement |
| 4 | `urlhaus_client.py` | URL/domain lookup |
| 5 | `phishtank_client.py` | URL-only |
| 6 | `shodan_client.py` | Gated enrichment — implement gate logic here |
| 7 | `anyrun_client.py` | First async sandbox — submit → poll pattern |
| 8 | `hybridanalysis_client.py` | DB + sandbox — most complex, builds on #7 |

---

## Out of Scope

These are not included in the current version but are candidates for future
iterations once the core pipeline is stable:

- User authentication and API key management for the Flask API itself
- A web-based frontend dashboard
- Webhook callbacks for async sandbox completion
- Bulk IOC upload via CSV file ingestion
- Automatic IOC extraction from raw log files or emails

## License

MIT License
