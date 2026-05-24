# Tech Stack

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

## Common Commands

```bash
# Install dependencies
uv sync

# Run the development server
uv run flask --app app run --debug

# Run all tests
uv run pytest

# Run a specific test file
uv run pytest tests/test_clamav.py -v

# Lint
uv run ruff check .

# Add a runtime dependency
uv add <package>

# Add a dev dependency
uv add --dev <package>
```

## Database Migrations (Alembic)

```bash
# Apply all pending migrations
uv run alembic upgrade head

# Roll back one migration
uv run alembic downgrade -1

# Auto-generate a migration from a schema change
uv run alembic revision --autogenerate -m "describe_change"

# Check current revision
uv run alembic current
```

`alembic.ini` has a blank `sqlalchemy.url` intentionally — `migrations/env.py` reads `DATABASE_URL` from `.env` at runtime so credentials are never in version control.

## Docker

```bash
# Full stack: app + PostgreSQL + ClamAV
docker compose up --build
```

Migrations run automatically on app container startup before Flask accepts traffic. ClamAV downloads virus definitions on first start (~2 min before file scanning works).

## Configuration

All secrets and config are loaded from `.env` into a frozen `@dataclass` in `config.py`. The app raises a clear `EnvironmentError` listing every missing key before accepting traffic. Never hardcode credentials — always use `.env`.

## Async Pattern

- Flask routes use `asyncio.run()` to drive async scanner calls
- All scanner clients are `async def` and called via `asyncio.gather()` for concurrency
- `pyclamd` (synchronous) is wrapped in `asyncio.to_thread()` to avoid blocking the event loop
- Batch scanning uses `asyncio.Semaphore(5)` to cap concurrent IOC scans (tunable via `BATCH_CONCURRENCY`)
