# authentication-service-v2

New authentication service, built bottom-up from the DB design phases in
`../authentication-service-src/docs/db-phases/`. No code from the earlier trees is used.

**Status (2026-10-25): slice 1 done.** Schema phase 1 (Flyway `V1__identity.sql`) and the
registration API `POST /internal/v1/callback/authentication-creation` (contract §1 of
`new-customer-onboarding-api-plan.md`), off by default.

Flow: reserve → Customer profile check (ELIGIBLE, verified phone/email) → Keycloak user created
**disabled** → permanent password set → SMS `ACCEPTED` → user enabled → identity + `READY`.
A retry with the same data returns the same `requestId`; an unfinished earlier attempt returns
503 and calls nobody (manual reconciliation). The password is never stored or logged.

**Known gaps:**
- No `passwordChangeRequired` flag: the password-change flow was removed, so the SMS password is
  a normal password.
- The endpoint has no caller authentication yet; enable it only on an internal network.
- If enabling the Keycloak user succeeds but the identity insert then finds the username taken,
  the Keycloak user stays enabled without an Auth identity (reported as conflict; needs cleanup).
- No test boots the whole application against a real MySQL yet.

## Build

Java 25, Maven 3.9, Docker for the MySQL integration tests:

```bash
mvn -o verify
```

Last run (2026-10-25): 93 unit tests (service, value types, 3 HTTP adapters with
`MockRestServiceServer`, web with MockMvc, configuration, ArchUnit) and `JdbcRegistrationStoreIT`
6 tests against MySQL 8.4 (Testcontainers): 0 failures, 0 skipped. No real Customer, Keycloak or
Notification service was called.

## Configuration

| Variable | Meaning |
|---|---|
| `AUTH_DB_URL`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD` | MySQL 8.4 connection |
| `AUTH_REGISTRATION_ENABLED` | `true` to expose registration (default `false`) |
| `AUTH_REGISTRATION_DIGEST_KEY_BASE64` | HMAC key (≥ 32 bytes) for the stored request digest |
| `AUTH_CUSTOMER_ORIGIN`, `AUTH_CUSTOMER_SERVICE_TOKEN` | Customer service; profile path `auth.registration.customer.profile-path` |
| `AUTH_KC_BASE_URL`, `AUTH_KC_REALM`, `AUTH_KC_ADMIN_CLIENT_ID`, `AUTH_KC_ADMIN_CLIENT_SECRET` | Keycloak Admin (service account allowed to manage users) |
| `AUTH_NOTIFICATION_ORIGIN`, `AUTH_NOTIFICATION_SERVICE_TOKEN` | Notification SMS; path `auth.registration.notification.sms-path` |

Timeouts default to 3 s per partner; no call is retried.
