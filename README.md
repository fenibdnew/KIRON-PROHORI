# KIRON PROHORI (কিরণ প্রহরী) — Independent Cyber Threat Intelligence Platform

**Version:** `0.1.0`  
**Budget Policy:** **Strict $0.00 Hard Cap** (No paid APIs, no paid cloud infrastructure, no runtime paid AI inference, no credit card required)  
**Languages:** Bilingual English (`en`) & Bengali (`বাংলা` / `bn`)

---

## 1. Mission & Non-Affiliation Declaration

**KIRON PROHORI** helps IT technicians, security researchers, small businesses, and ordinary users understand publicly documented cybersecurity threats, software vulnerabilities, malware distribution indicators, and online scams.

> **IMPORTANT PRODUCT IDENTITY & NON-AFFILIATION NOTICE:**  
> KIRON PROHORI is an **independent defensive cybersecurity intelligence product**. It is **not** affiliated with, endorsed by, sponsored by, or operated by **CISA, NIST, MITRE/CVE, FIRST, abuse.ch, CIRCL, GitHub, Google**, or any government agency. All threat intelligence displayed is for defensive educational and informational triage only and does not constitute legal compliance certification or a guarantee of safety.

---

## 2. Core Platform Architecture (16 Modules + 4 Legal Declarations)

1. **Dashboard (`dashboard`)**: Unified defensive posture overview, public feed synchronization status, and local watchlist summary.
2. **CVE Explorer (`cve-explorer`)**: Search by CVE ID, vendor, and product; filter by CVSS v3.1/v4.0 score & severity; view CWEs, affected CPEs, references, KEV cross-match status, and export RFC-4180 CSV. Missing fields are explicitly shown as `Unknown`.
3. **CISA KEV Tracker (`cisa-kev`)**: Real imported Known Exploited Vulnerabilities catalog with vendor/product/date filters, snapshot diffing (`NEWLY_IMPORTED` identification), required actions, and strict preservation of `Unknown` ransomware campaign status (`Unknown` is never interpreted as `No`).
4. **Malware Intelligence (`malware-intel`)**: Public, authorized defanged threat indicators (`hxxps://...[.]`), 64-hex SHA-256 lookup via CIRCL Public Hashlookup, and zero payload download/execution.
5. **Scam & Phishing Intelligence (`scam-phishing`)**: User-submitted scam reports with mandatory moderation queue, static suspicious URL lexical parser, public threat feed cross-matching, PII redaction, and a **Scam Report Appeal & False-Positive Contact Mechanism**.
6. **Security Advisories (`security-advisories`)**: Public GitHub Security Advisories (GHSA) and CISA KEV directives with official source links, publication dates, category filters, and pagination.
7. **URL Inspector (`url-inspector`)**: 100% static client-side URL decomposition, domain normalization, IDN Punycode homograph detection, `@` authority deception check, nested redirect parameter extraction, and consent-guarded public feed matching (`No Match = UNKNOWN, Never SAFE`).
8. **Hash Lookup (`hash-lookup`)**: Local browser WebCrypto API (`window.crypto.subtle.digest('SHA-256', buffer)`) file hash calculator with zero file uploads, MD5/SHA-1/SHA-256 format validator, and optional public hash reputation lookup.
9. **Security Checklist (`security-checklist`)**: 6 defensive hardening tracks (Account Security, Password Manager Awareness, Multi-Factor Authentication, Backup & Software Updates, Small Business Security, and Computer Service Technician Checklist) persisted locally in browser storage.
10. **Report Center (`report-center`)**: Client-side downloadable **RFC-4180 CSV** and **native `%PDF-1.4` PDF** report generator with report date, official source references, and mandatory non-affiliation disclaimer.
11. **My Watchlist (`my-watchlist`)**: Save CVEs and follow vendors/products with a personalized vulnerability match dashboard.
12. **Notifications (`notifications`)**: Zero-cost in-app notification center with category filters (`watchlist_match`, `moderation_update`, `security_notice`, `system`) and read-state management (no paid email/SMS gateways).
13. **Data Sources (`data-sources`)**: Transparency registry for all connected `$0` public threat intelligence feeds.
14. **Admin Center (`admin-center`)**: Server- and Firestore-authorized governance workspace featuring Real Admin Metrics, User List & PII-Masked Emails, Authoritative Role Management (`/roles/{uid}`), 4-State Scam Report Moderation (`pending`, `approved`, `rejected`, `needs_more_info`), Manual Sync Controls, Sync History & Error Logs, Data Freshness Matrix, Feedback/Appeal Triage, App Settings, Immutable Audit Log Viewer, and System Health Telemetry.
15. **Settings (`settings`)**: Bilingual language toggle (`English` / `বাংলা`), high-contrast slate/dark theme switch, and private user profile editor.
16. **Help & Documentation (`help-docs`)**: Defensive cybersecurity glossary and live Phase 6 QA, Security Audit & Deployment Readiness verification matrix.

---

## 3. External API Dependencies & Free-Tier Restrictions ($0.00 Budget)

| Public Service / API | Authentication | Cost Tier | Free-Tier Limits & Quotas | Fallback Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **CISA KEV Official JSON** | None (Public JSON) | `$0.00` | Static public JSON catalog; manual refresh + server cache | Preserves previous cached catalog on network error; marks `STALE DATA` |
| **NIST NVD API 2.0** | Optional (`NVD_API_KEY` optional) | `$0.00` | **5 req / 30s** (unauthenticated) or **50 req / 30s** (free API key); 6s server throttle + 10m cache | Serves cached NVD map and Firestore `/cves` records on rate-limit/timeout |
| **FIRST EPSS v1 API** | None (Public REST) | `$0.00` | Public community quota; batched up to 15–25 CVEs per request | Gracefully omitted if unreachable without blocking CVE lookups |
| **GitHub Security Advisories (GHSA)** | None (Public REST) | `$0.00` | **60 req / hour** unauthenticated; cached for 10 minutes | Serves cached GHSA records + CISA KEV directives + Firestore `/security_advisories` |
| **CIRCL Public Hashlookup** | None (Public REST) | `$0.00` | On-demand single 64-hex SHA-256 lookup (no bulk polling) | Local WebCrypto SHA-256 hashing & Firestore `/threat_indicators` work 100% offline |
| **abuse.ch URLhaus API** | Optional (`URLHAUS_AUTH_KEY`) | `$0.00` | Non-commercial community fair-use quota when configured | Displays honest `NOT CONFIGURED` status if key is omitted; never blocks other modules |
| **Firebase Auth & Cloud Firestore** | Google Sign-In + Security Rules | `$0.00` | **Spark No-Cost Plan**: 1 GiB storage, 50k reads/day, 20k writes/day, 20k deletes/day | Clearly labeled `LOCAL DEMO MODE (Not Permanently Saved)` if unconfigured |

---

## 4. Environment Variables (`.env.example`)

Copy `.env.example` to `.env` for local development. **Never commit real credentials.** Both `NVD_API_KEY` and `URLHAUS_AUTH_KEY` are **optional**—the application starts and runs with zero environment variables configured.

```bash
cp .env.example .env
```

Placeholder variables in `.env.example`:
- `APP_URL="MY_APP_URL"`
- `GEMINI_API_KEY="MY_GEMINI_API_KEY"` *(Not invoked at runtime; 0 runtime LLM calls)*
- `NVD_API_KEY="MY_NVD_API_KEY"` *(Optional server-side key)*
- `URLHAUS_AUTH_KEY="MY_URLHAUS_AUTH_KEY"` *(Optional server-side key)*

---

## 5. Installation, Verification & Automated Testing

### Prerequisites
- Node.js `v20+` or `v22+`
- npm `v10+`

### Install Dependencies
```bash
npm install
```

### Run TypeScript Type Check & Firestore Rules Security Linter
```bash
npm run lint
npm run lint:rules
```

### Run All 5 Automated Verification Suites (Connectors, Intelligence, Toolkit, Admin Governance, and Phase 6 QA/Security/Cost)
```bash
npx tsx src/connectors/connectors.test.ts
npx tsx src/intelligence/intelligence.test.ts
npx tsx src/toolkit/toolkit.test.ts
npx tsx src/admin/admin.test.ts
npx tsx src/qa/phase6.test.ts
```

### Start Local Development Server (Port 3000)
```bash
npm run dev
```

### Build for Production
```bash
npm run build
```

---

## 6. Firestore Security Rules (`firestore.rules`)

The file `/firestore.rules` enforces a zero-trust security posture across all 14 collections (`users`, `roles`, `cves`, `kev_entries`, `threat_indicators`, `security_advisories`, `scam_reports`, `watchlists`, `notifications`, `data_sources`, `sync_logs`, `audit_logs`, `feedback`, `app_settings`):
- **Global Default-Deny Catch-All**: `match /{document=**} { allow read, write: if false; }`
- **No Client-Side Role Escalation**: `/users/{userId}` strictly forbids any `role` field via `hasOnly(['uid', 'email', 'displayName', 'organization', 'preferredLanguage', 'createdAt', 'updatedAt'])`. Authoritative roles reside exclusively in `/roles/{userId}` (Admin-only writes).
- **Mandatory Scam Report Moderation**: New reports in `/scam_reports/{reportId}` must be created with `moderationStatus == 'pending'`. Public users can only read reports where `moderationStatus == 'approved'`.
- **Immutable Audit & Sync Ledgers**: `/audit_logs` and `/sync_logs` enforce `allow update, delete: if false;`.

To validate and deploy rules using the Firebase CLI (on a no-cost Spark project):
```bash
npm run lint:rules
npx firebase deploy --only firestore:rules
```

---

## 7. Zero-Cost Deployment Instructions

> **STRICT COST GUARDRAIL:** Do **not** enable paid Cloud Billing, do **not** attach a credit card where paid overages can occur, and do **not** claim deployment succeeded unless your hosting provider explicitly returns a live deployment confirmation URL.

### Option A: Eligible Google Cloud Starter Tier / No-Cost Full-Stack Environment
When deploying to an eligible no-cost container/applet environment (such as Google AI Studio Applet hosting or an eligible no-cost Starter Tier):
1. Ensure `.env` does not contain hardcoded secrets.
2. Build the frontend assets:
   ```bash
   npm run build
   ```
3. Start the production Express server (`server.ts` serves `dist/` and mounts `/api/security/*`, `/api/connectors/*`, and `/api/intelligence/*` on port `3000`):
   ```bash
   NODE_ENV=production npm start
   ```
4. Verify the deployment by checking `GET /api/security/health` (must return `HTTP 200` with `"budgetMode": "STRICT_ZERO_COST ($0.00)"`).

### Option B: Free Static Demo Fallback (If Cloud Starter Tier Is Unavailable)
If a no-cost Node.js container tier is unavailable, deploy the compiled `dist/` directory to any **100% free static host** (such as **GitHub Pages**, **Firebase Hosting Spark No-Cost Tier**, or **Cloudflare Pages** — no credit card required):
1. Build the static bundle:
   ```bash
   npm run build
   ```
2. Deploy the `dist/` folder to your free static host (e.g., `npx firebase deploy --only hosting` on a Spark project or GitHub Pages action publishing `dist/`).
3. **Honest Static Fallback Behavior**:
   - In Static Hosting Mode, `/api/*` Express backend routes are not present.
   - KIRON PROHORI automatically detects that `/api/security/health` is unreachable and displays **`STATIC DEMO FALLBACK (Backend Proxy Unavailable — Client-Side Tools & Direct Firestore Rules Active; Server Proxy Routes Offline)`** in the Admin Center and System Health panel.
   - It **never** pretends backend proxy connectors are running when hosted statically, while all client-side defensive tools (URL Inspector, WebCrypto SHA-256 Hash Calculator, 6-Track Security Checklists, CSV/PDF Report Generator) and direct Cloud Firestore Spark queries continue to work at `$0.00`.
