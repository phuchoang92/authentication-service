# authentication-service-v2

New authentication service, built bottom-up from the DB design phases in
`../authentication-service-src/docs/db-phases/`. No code from the earlier trees is used.

**Status (2026-10-25): slices 1 and 2 done** on [ARCHITECTURE.md](ARCHITECTURE.md) (layer-first
hexagonal, Spring Data JPA, Valkey sessions, localized errors). Schema phase 1 (Flyway
`V1__identity.sql`), the registration API `POST /internal/v1/callback/authentication-creation`
(contract §1 of `new-customer-onboarding-api-plan.md`) and password login / session / logout /
extend ([plan](docs/plans/slice-2-login-session.md)), each off by default.

| Path | Caller | Result |
|---|---|---|
| `POST /api/ns/v1/login` | app via BFF, no session | `201 {tokenEnvelope, status, idleExpiresAt, absoluteExpiresAt}`; `401 INVALID_CREDENTIALS`; `403 ACCOUNT_NOT_READY`; `503 LOGIN_UNAVAILABLE` |
| `POST /api/v1/logout` | app, `Authorization: Bearer k1.<43>` | `204`; `401 SESSION_REQUIRED` |
| `POST /internal/v1/sessions/extend` | BFF after admission (flow 16) | `200 {idleExpiresAt, absoluteExpiresAt}`; `400`; `410 SESSION_GONE`; `409 SESSION_CONFLICT`; `503` |

The token is `k1.<43 base64url>` and reaches the app only inside a compact JWE (`ECDH-ES`/`A256GCM`
to the P-256 `tokenEncryptionKey` the app sent). Valkey holds `session:v1:k1:<HMAC(token)>` with
`customerId, sessionId, deviceId?, status, channel`, deadlines and `sessionVersion`; idle 15 min
slides on extend, absolute 20 min never moves. The password is verified by Keycloak Direct Grant
(client secret) and the KC-signed ID token is checked against the realm JWKS.

Error messages are returned in the language of the `Accept-Language` header: `vi` (default) or
`en`; the catalogue is `src/main/resources/messages/errors_<lang>.properties`.

Flow: reserve → Customer profile check (ELIGIBLE, verified phone/email) → Keycloak user created
**disabled** → permanent password set → SMS `ACCEPTED` → user enabled → identity + `READY`.
A retry with the same data returns the same `requestId`; an unfinished earlier attempt returns
503 and calls nobody (manual reconciliation). The password is never stored or logged.

**Known gaps:**
- Slice 2 deliberately defers DD-06 pieces: DPoP/Kreq binding, Idempotency-Key, Auth receipt
  signature, Redis guards/generation, `private_key_jwt`, lockout (phase 2), trusted device (slice 3).
- `/api/ns` and `/internal` have no caller authentication yet.
- No `passwordChangeRequired` flag: the password-change flow was removed, so the SMS password is
  a normal password.
- The endpoint has no caller authentication yet; enable it only on an internal network.
- If enabling the Keycloak user succeeds but the identity insert then finds the username taken,
  the Keycloak user stays enabled without an Auth identity (reported as conflict; needs cleanup).

## Build

Java 25, Maven 3.9, Docker for the MySQL integration tests:

```bash
mvn -o verify
```

Last run (2026-10-25): 166 tests, 0 failures — 154 unit (domain state machines and value
objects, services with mocked ports, web/persistence/partner mappers, Valkey key vector and codec,
error catalogue, Keycloak admin + Direct Grant with a test-signed ID token, JWE sealer round trip,
`@WebMvcTest` slices incl. the session filter, configuration, 8 ArchUnit rules) and 12 on
Testcontainers (`RegistrationPersistenceAdapterIT` on MySQL 8.4, `ValkeySessionAdapterIT` on
`valkey/valkey:9.1`, `ApplicationBootIT` booting everything against MySQL + Valkey: register →
login → decrypt envelope → extend → logout). No real Customer, Keycloak or Notification service was
called.

## Configuration

| Variable | Meaning |
|---|---|
| `AUTH_DB_URL`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD` | MySQL 8.4 connection |
| `AUTH_REGISTRATION_ENABLED` | `true` to expose registration (default `false`) |
| `AUTH_REGISTRATION_DIGEST_KEY_BASE64` | HMAC key (≥ 32 bytes) for the stored request digest |
| `AUTH_CUSTOMER_ORIGIN`, `AUTH_CUSTOMER_SERVICE_TOKEN` | Customer service; profile path `auth.registration.customer.profile-path` |
| `AUTH_KC_BASE_URL`, `AUTH_KC_REALM`, `AUTH_KC_ADMIN_CLIENT_ID`, `AUTH_KC_ADMIN_CLIENT_SECRET` | Keycloak Admin (service account allowed to manage users) |
| `AUTH_NOTIFICATION_ORIGIN`, `AUTH_NOTIFICATION_SERVICE_TOKEN` | Notification SMS; path `auth.registration.notification.sms-path` |

| `AUTH_LOGIN_ENABLED` | `true` to expose login/logout/extend (default `false`) |
| `AUTH_VALKEY_URL` | `redis://host:port` of the session store (default `redis://localhost:6379`) |
| `AUTH_KC_LOGIN_CLIENT_ID`, `AUTH_KC_LOGIN_CLIENT_SECRET` | Direct Grant client (`authentication-service`) |
| `AUTH_SESSION_LOOKUP_HMAC_KEY_K1_BASE64` | ≥32-byte HMAC key for the `k1` session lookup (shared with the BFF) |

Timeouts default to 3 s per partner; no call is retried.
