# IOC Scanner — Product Overview

A self-hosted threat intelligence REST API for security analysts and SOC teams. It accepts IP addresses, URLs, domains, file hashes, and file uploads, then fans them out concurrently against eight intelligence sources, returning a unified verdict, confidence score, and enrichment data. All results are cached in PostgreSQL so repeated lookups never hit external APIs.

## Core Capabilities

- **Single IOC scan** (`/scan/full`): Concurrent multi-source scan with aggregated verdict
- **Targeted scan** (`/scan/single`): One IOC against one named source
- **Batch scan** (`/scan/batch`): Up to 100 IOCs submitted async, polled via `/batch/<batch_id>`
- **Cache management**: Results cached by `(ioc, source)`; explicit eviction via `DELETE /results/<ioc>`

## Intelligence Sources

| Source | IOC Types | Notes |
|---|---|---|
| ClamAV | File | Local, no quota, runs first |
| VirusTotal | IP, URL, Domain, Hash | DB lookup |
| AbuseIPDB | IP | DB lookup |
| URLhaus | URL, Domain | DB lookup |
| PhishTank | URL | DB lookup |
| Shodan | IP | Gated — only called when another source already flagged the IP |
| ANY.RUN | URL, File | Sandbox detonation, opt-in |
| Hybrid Analysis | IP, URL, Domain, Hash, File | DB lookup + optional sandbox |

## Verdict Engine

All scanner results normalize to a `CTIResult` dataclass. `compute_verdict()` produces a single verdict (`clean`, `suspicious`, `malicious`, `unknown`), a confidence score (0–100), contributing sources, and errored sources. Sandbox sources carry higher weight than passive DB lookups; ClamAV carries maximum confidence.

## Quota Management Rules

- **Shodan**: Only called when `ioc_type == ip` AND another source already flagged it
- **ClamAV gate**: A ClamAV `FOUND` skips ANY.RUN and Hybrid Analysis entirely
- **Sandbox escalation**: Sandbox detonation is opt-in via `"sandbox": true`
- **Caching**: Every result is upserted after first scan; cache is never stale by accident
