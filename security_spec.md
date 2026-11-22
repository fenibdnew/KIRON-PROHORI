# KIRON PROHORI — Phase 0 Payload-First Security TDD Specification

## 1. Data Invariants & Trust Boundaries

1. **Zero Client-Side Role Trust (`/users/{userId}` & `/roles/{userId}`)**:
   - The `/users/{userId}` document is strictly forbidden from containing a `role` or `isAdmin` field (`hasOnly(['uid', 'email', 'displayName', 'organization', 'preferredLanguage', 'createdAt', 'updatedAt'])`).
   - Authoritative RBAC roles live exclusively in `/roles/{userId}` and can ONLY be created, updated, or deleted by an authenticated verified Administrator (`isAdmin()`).
   - No user can self-assign or escalate their role to `admin`, `moderator`, or `analyst`.

2. **PII Isolation (`/users/{userId}`)**:
   - Because `/users/{userId}` stores the user's `email` and `organization`, blanket `isSignedIn()` reads or lists are strictly prohibited.
   - `get` is restricted to `isOwner(userId) || isAdmin()`, and `list` is restricted to `isBootstrappedAdmin()`.

3. **Public Read-Only Threat Intelligence (`/cves`, `/kev_entries`, `/threat_indicators`, `/security_advisories`)**:
   - Unauthenticated visitors and normal users have read-only access (`get`, `list`).
   - Only verified Administrators (`isAdmin()`) can create, update, or delete records in these collections, and every write must pass strict schema, key allowlist, string length, and server timestamp checks.

4. **Pending Moderation Invariant (`/scam_reports/{reportId}`)**:
   - When an authenticated verified user submits a scam report, `incoming().reporterUid == request.auth.uid` AND `incoming().moderationStatus == 'pending'` AND `incoming().moderatorNotes == ''` AND `incoming().reviewedBy == ''` are mandatory.
   - A normal user cannot create an already-approved scam report or update `moderationStatus`.
   - Public readers can only read or list reports where `resource.data.moderationStatus == 'approved'` (while the reporter can view their own pending reports).

5. **User-Owned Record Isolation (`/watchlists/{watchlistId}`, `/notifications/{notificationId}`, `/feedback/{feedbackId}`)**:
   - Every document must bind `userId == request.auth.uid`.
   - `allow list` rules explicitly enforce `resource.data.userId == request.auth.uid || isBootstrappedAdmin()` (never delegating filtering to the client and never placing `get()`/`exists()` inside `allow list`).

6. **Admin-Only Source & Settings Governance (`/data_sources/{sourceId}`, `/sync_logs/{logId}`, `/app_settings/{settingId}`)**:
   - `/data_sources` and `/app_settings` are publicly readable for transparency, while mutations require `isAdmin()` and enforce `costTier == 'FREE_PUBLIC_ZERO_COST'`.
   - `/sync_logs` and `/audit_logs` are strictly append-only (`allow update, delete: if false;`).

---

## 2. The "Dirty Dozen" Adversarial Payloads

| # | Attack Vector | Target Path | Malicious Payload | Expected Result |
| :- | :------------ | :---------- | :---------------- | :-------------- |
| 1 | **Self-Admin Privilege Escalation** | `/roles/user_alice` | `{"uid": "user_alice", "role": "admin", "assignedBy": "user_alice", "createdAt": "SERVER_TIME", "updatedAt": "SERVER_TIME"}` by non-admin `user_alice` | `PERMISSION_DENIED` |
| 2 | **Shadow Role Field in User Profile** | `/users/user_alice` | `{"uid": "user_alice", "email": "alice@example.com", "displayName": "Alice", "organization": "SecOps", "preferredLanguage": "en", "role": "admin", "createdAt": "SERVER_TIME", "updatedAt": "SERVER_TIME"}` | `PERMISSION_DENIED` |
| 3 | **Cross-User PII Harvesting** | `/users/user_bob` | Authenticated `user_alice` calls `getDoc(doc(db, 'users', 'user_bob'))` | `PERMISSION_DENIED` |
| 4 | **Unverified Email Admin Spoof** | `/data_sources/src_1` | Attacker with `email: "mdarifab50@gmail.com"` but `email_verified: false` attempts `setDoc` | `PERMISSION_DENIED` |
| 5 | **Unauthorized CVE Injection** | `/cves/CVE-2026-9999` | Normal authenticated user attempts to write a fake CVE entry | `PERMISSION_DENIED` |
| 6 | **Scam Report Pre-Approval Bypass** | `/scam_reports/rep_1` | Normal user creates report with `{"moderationStatus": "approved", ...}` | `PERMISSION_DENIED` |
| 7 | **Unapproved Scam Report Scraping** | `/scam_reports/rep_pending` | Unauthenticated user attempts `getDoc` on a report with `moderationStatus == "pending"` | `PERMISSION_DENIED` |
| 8 | **Cross-User Watchlist Scraping** | `/watchlists` | `user_alice` runs unconstrained `getDocs(collection(db, 'watchlists'))` without `where('userId', '==', 'user_alice')` | `PERMISSION_DENIED` |
| 9 | **Watchlist Owner Hijack Update** | `/watchlists/wl_1` | `user_alice` updates `userId` to `"user_bob"` or modifies `createdAt` | `PERMISSION_DENIED` |
| 10 | **Audit Log Tampering / Deletion** | `/audit_logs/aud_1` | Even an authenticated user or admin attempts `updateDoc` or `deleteDoc` on an existing audit log | `PERMISSION_DENIED` |
| 11 | **Paid Data Source Cost-Tier Violation** | `/data_sources/src_paid` | Admin attempts to create a source with `costTier: "PAID_ENTERPRISE"` | `PERMISSION_DENIED` |
| 12 | **Path ID Poisoning / Oversized Payload** | `/watchlists/bad$id!@#` | Authenticated user creates document with invalid ID characters or 50KB `targetValue` | `PERMISSION_DENIED` |
