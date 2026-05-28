# Project Structure

```
iocscanner/
├── app.py                      # Flask app factory + all route definitions
├── config.py                   # Loads .env → frozen Config @dataclass
├── models.py                   # CTIResult dataclass + compute_verdict()
├── db.py                       # PostgreSQL connection pool + upsert helpers
├── validators.py               # Request input validation
├── cache.py                    # Cache read/write logic (wraps db.py)
├── batch.py                    # Batch job orchestration + semaphore logic
├── logger.py                   # Structured JSON logging
│
├── clamav_client.py            # Local AV scan via pyclamd (asyncio.to_thread)
├── virustotal_client.py
├── abuseipdb_client.py
├── urlhaus_client.py
├── phishtank_client.py
├── shodan_client.py            # Gated — IP only, flagged IOCs only
├── anyrun_client.py            # Sandbox — submit → poll → parse
├── hybridanalysis_client.py    # DB lookup fast path + optional sandbox
│
├── migrations/                 # Alembic migrations
│   ├── env.py                  # Reads DATABASE_URL from .env at runtime
│   ├── alembic.ini             # sqlalchemy.url intentionally blank
│   └── versions/
│       ├── 0001_create_cti_results.py
│       ├── 0002_create_shodan_usage.py
│       ├── 0003_create_batch_jobs.py
│       └── 0004_create_clamav_results.py
│
├── tests/
│   ├── test_models.py
│   ├── test_clamav.py
│   ├── test_virustotal.py
│   ├── test_abuseipdb.py
│   ├── test_urlhaus.py
│   ├── test_phishtank.py
│   ├── test_shodan.py
│   ├── test_anyrun.py
│   └── test_hybridanalysis.py
│
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── .env                        # Never committed — copy from .env.example
```

## Conventions

**Scanner clients** (`*_client.py`): One file per intelligence source. Each exposes an `async def scan(ioc, ioc_type, ...) -> CTIResult` function. Clients are independent — they must not import each other.

**Models** (`models.py`): `CTIResult` is the single shared data contract between all scanner clients and the verdict engine. All scanners normalize their raw API responses into `CTIResult` before returning.

**Routing** (`app.py`): All Flask routes live here. Route handlers are thin — they validate input (via `validators.py`), check cache (via `cache.py`), dispatch to scanner clients, and return JSON. Business logic belongs in the appropriate module, not in route handlers.

**Config** (`config.py`): The only place environment variables are read. All other modules import the `Config` dataclass instance — never call `os.getenv()` directly outside `config.py`.

**Migrations**: Named with a zero-padded numeric prefix (`0001_`, `0002_`, ...). Always auto-generate via `alembic revision --autogenerate` rather than writing raw SQL by hand.

**Tests**: One test file per module/client. Tests for scanner clients should mock external HTTP calls — never make real API requests in tests.

**Error handling**: A single source failing must never block a `/scan/full` or `/scan/batch` response. Errors are captured in `CTIResult.error` and surfaced in `verdict.errors`.

**Secrets**: All API keys and DB credentials live exclusively in `.env`. The `.env` file is gitignored. Never log or echo secret values.

**Github workflow**: Create two branches [staging, develop]. New features are done in the develop branch, the new features are tested in the staging branch. When all tests are good, then the features are pushed to the main branch.
