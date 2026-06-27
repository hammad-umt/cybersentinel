# CyberSentinel Backend — Test Suite

Automated tests for the FastAPI backend. Every test has a **fixed expected outcome** (pass or fail) and runs in CI without ML model files, Supabase, or external API keys.

## Run locally

```powershell
cd cybersentinel-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest tests/ -v
```

Expected result: **all tests passed**.

## Test case index

| ID | Module | Description | Expected |
|----|--------|-------------|----------|
| TC-AUTH-01 | Auth | Login with valid email/password | HTTP 200 + JWT |
| TC-AUTH-02 | Auth | Login with wrong password | HTTP 401 |
| TC-AUTH-03 | Auth | Public registration | HTTP 201, role Analyst |
| TC-AUTH-04 | Auth | Duplicate email registration | HTTP 400 |
| TC-AUTH-05 | Auth | GET /auth/me with token | HTTP 200 |
| TC-AUTH-06 | Auth | GET /auth/me without token | HTTP 401 |
| TC-AUTH-07 | Auth | Logout revokes token | HTTP 200 then 401 |
| TC-AUTH-08 | Auth | Password reset flow | Reset OK, old password fails |
| TC-AUTH-09 | Auth | Invalid reset token | valid=false, reset 400 |
| TC-AUTH-10 | Auth | Forgot-password without email config | HTTP 503 |
| TC-UNIT-AUTH-01..05 | Auth service | Password hash, JWT, reset tokens | Unit assertions |
| TC-API-01 | Security | Protected routes without JWT | HTTP 401 |
| TC-API-02 | Security | Protected routes with admin JWT | HTTP 200 |
| TC-API-03 | Security | Invalid Bearer token | HTTP 401 |
| TC-RBAC-01..07 | RBAC | Admin vs Analyst permissions | 200 or 403 |
| TC-DASH-01..03 | Dashboard | SOC summary KPIs | HTTP 200 |
| TC-PKT-01..07 | Packet | Classify, events, batch CSV | 200/400/401 |
| TC-FW-01..09 | Firewall | Analyze, ingest, alerts, intel | 200/401/404 |
| TC-THR-01..06 | Threat | Score, top, queue | 200/401/422 |
| TC-INTEL-01..04 | Intel | File hash, URL scan | 200/401/422 |
| TC-CAP-01..07 | Capture | Interfaces, status, RBAC import | 200/400/401/403 |
| TC-RESP-01..04 | Response | Dry-run actions, audit log | HTTP 200 |
| TC-COP-01..04 | Copilot | Ask/query, validation | 200/401/422 |
| TC-RPT-01..03 | Reports | PDF export | 200 + %PDF |
| TC-ADM-01..03 | Admin | Reload models RBAC | 200/401/403 |
| TC-SYS-01..03 | System | Health, OpenAPI Bearer scheme | HTTP 200 |
| TC-UNIT-SEC-01..03 | Security | Role mapping helpers | Unit assertions |

## Design notes

- **In-memory SQLite** — no cloud database required for tests.
- **Fake ML models** (`tests/fakes.py`) — packet/firewall routes always get HTTP 200 in CI.
- **No loose assertions** — tests never accept `status in (200, 503)`; outcomes are explicit.

## GitHub Actions

Workflow: `.github/workflows/backend-tests.yml` runs on every push/PR.
