# KIRON PROHORI (কিরণ প্রহরী) — Repository Architecture (`/docs/ARCHITECTURE.md`)

**Independent Cyber Threat Intelligence Platform** (`v0.1.0` · Strict `$0.00` Budget)

> **Non-Affiliation Notice:** KIRON PROHORI is an independent defensive cybersecurity intelligence and education product. It is **not** affiliated with, endorsed by, or operated by CISA, NIST, MITRE/CVE, FIRST, abuse.ch, CIRCL, GitHub, Google, or any government agency.

---

## 1. Modular Directory Layout

```text
kiron-prohori/
│
├── client/
│   ├── components/         # Shared UI primitives, badges, disclaimers, ErrorBoundary, QA panel
│   ├── layouts/            # Responsive SOC command-center shell (Header, Sidebar, Footer)
│   ├── pages/              # OverviewDashboard, ModulePlaceholderPage, LegalTrustPages
│   ├── modules/
│   │   ├── dashboard/      # Executive threat overview & live telemetry summary
│   │   ├── cve/            # NIST NVD 2.0 search, CVSS/CWE/CPE filter, RFC-4180 CSV export
│   │   ├── kev/            # Keyless CISA KEV catalog tracker, snapshot diffing, Unknown != No
│   │   ├── malware/        # Authorized threat indicators & 64-hex SHA-256 lookup
│   │   ├── scam/           # Suspicious URL parser, threat feed matcher, moderated scam alerts
│   │   ├── toolkit/        # Static URL Inspector, WebCrypto SHA-256, 6 Checklists, CSV/PDF reports
│   │   └── admin/          # RBAC Admin Center, PII-scrubbed moderation, freshness, audit logs
│   ├── hooks/              # AppContext (EN/BN i18n, navigation) & SecurityContext (Auth/RBAC)
│   ├── services/           # Firebase Auth/Firestore client SDK & startup connection checks
│   ├── locales/            # Bilingual English ('en') and Bengali ('bn') translation dictionary
│   └── styles/             # High-contrast defensive SOC theme tokens
│
├── server/
│   ├── routes/             # Canonical API route registry (/api/security/*, /api/connectors/*, /api/toolkit/*)
│   ├── controllers/        # Zero-key startup diagnostics & connector status controllers
│   ├── middleware/         # Defensive HTTP headers & sliding-window IP rate limiter
│   ├── connectors/         # CISA KEV, NIST NVD 2.0, FIRST EPSS v1, URLhaus, GitHub, CIRCL connectors
│   ├── services/           # Non-destructive cache upsert, KEV snapshot diffing, PII scrubbing
│   └── validators/         # Input validators, optional-secret guard, SSRF outbound host allowlist
│
├── shared/
│   ├── types/              # Domain, Firestore, connector, intelligence, toolkit, and admin types
│   ├── schemas/            # Input validation schemas & 14 Firestore collection field contracts
│   └── constants/          # Allowed outbound SSRF hosts, zero-cost policy, non-affiliation statement
│
├── firebase/
│   └── firestore.rules     # 574-line zero-trust Firestore security rules (synced with /firestore.rules)
│
├── tests/
│   └── run-all.ts          # Unified automated verification suite runner
├── docs/
│   ├── ARCHITECTURE.md     # Architectural specification & directory guide
│   └── FREE_TIER_LIMITS.md # External API terms, rate limits, and zero-cost fallback matrix
├── .env.example            # Zero-key startup template (no NVD_API_KEY or URLHAUS_AUTH_KEY required)
├── README.md               # Installation, verification, and zero-cost deployment documentation
└── package.json            # Scripts & dependencies
```

---

## 2. Zero-Key Startup & Strict $0 Cost Policy

1. **CISA KEV (`cisa_kev`)**: Connects directly to `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` on server startup without any API key.
2. **NIST NVD API 2.0 (`nist_nvd`)**: Operates out-of-the-box without `NVD_API_KEY` on the official unauthenticated tier (`5 requests / 30s` rolling window) with automatic `6,000ms` server request spacing and a `10-minute` query cache.
3. **abuse.ch URLhaus (`urlhaus`)**: Remains completely optional and displays `NOT CONFIGURED` when `URLHAUS_AUTH_KEY` is absent, without blocking startup or any other module.
4. **No Fake or Placeholder Keys**: `getOptionalConfiguredSecret()` rejects empty strings, short strings, or placeholder patterns (`MY_*`, `YOUR_*`, `placeholder`, `fake`, `dummy`).
