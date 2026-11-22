# KIRON PROHORI — External API Free-Tier Limits & Fallback Matrix (`/docs/FREE_TIER_LIMITS.md`)

All integrations operate strictly at **$0.00 cost** without credit cards or paid billing upgrades.

| Service | Endpoint Host | Required Startup Key | Free-Tier Rate Limit | Fallback / Protection |
| :--- | :--- | :--- | :--- | :--- |
| **CISA KEV Catalog** | `www.cisa.gov` | **None** | Public static JSON feed | Auto-synced on server startup; preserves last-known-good snapshot on outage |
| **NIST NVD API 2.0** | `services.nvd.nist.gov` | **None** (`NVD_API_KEY` optional) | **5 req / 30s** (unauthenticated) | Enforces 6,000ms server request spacing and 10-minute response caching |
| **FIRST EPSS API v1** | `api.first.org` | **None** | ~1,000 req / min public REST limit | Batches CVE lookups; displays mandatory 30-day probability estimation disclaimer |
| **GitHub Advisory DB** | `api.github.com` | **None** | **60 req / hr** per IP (unauthenticated) | Caches synchronized advisories and surfaces HTTP 403/429 rate-limit status honestly |
| **CIRCL Hashlookup** | `hashlookup.circl.lu` | **None** | Fair-use public REST lookup | Invoked only after explicit user consent for a validated 64-hex SHA-256 digest |
| **abuse.ch URLhaus** | `urlhaus-api.abuse.ch` | **None** (`URLHAUS_AUTH_KEY` optional) | Community fair-use limit | Reports `NOT CONFIGURED` when key is absent; never blocks other modules |
| **Firebase Auth & Firestore** | `firestore.googleapis.com` | **None** (Spark Plan) | **50k reads/day, 20k writes/day, 1 GiB** | Automatically falls back to clearly labeled **Local Demo Mode** if unavailable |
