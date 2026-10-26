# authentication-service

New authentication service, built bottom-up from the DB design phases in
`../authentication-service-src/docs/db-phases/`. No code from the earlier trees is used.

Development rules: [architecture and package boundaries](ARCHITECTURE.md),
[code conventions and readability examples](CODE_CONVENTIONS.md).

**Status (2026-10-26): slices 1–6 done, code aligned with
[CODE_CONVENTIONS.md](CODE_CONVENTIONS.md)** on [ARCHITECTURE.md](ARCHITECTURE.md) (layer-first
hexagonal under `domain` / `application` / `infrastructure`, business enums in `domain.enums`,
Spring Data JPA, Valkey sessions, localized errors). Schema phases 1–3 (Flyway
`V1__identity.sql`, `V2__password_lockout.sql`, `V3__trusted_device.sql`), the registration API
`POST /internal/v1/callback/authentication-creation` (contract §1 of
`new-customer-onboarding-api-plan.md`), password login / session / logout / extend
([plan](docs/plans/slice-2-login-session.md)), password lockout with CAPTCHA
([plan](docs/plans/slice-3-password-lockout.md)) and trusted devices
([plan](docs/plans/slice-4-trusted-device.md)) and device enrollment init → verify → confirm with
FACE ([plan](docs/plans/slice-5-enrollment.md)) and approval of a new device by the current primary
device through a QR token ([plan](docs/plans/slice-6-device-approval.md)), each off by default.

| Path | Caller | Result |
|---|---|---|
| `POST /api/ns/v1/login` | app via BFF, no session | `201 {tokenEnvelope, status, idleExpiresAt, absoluteExpiresAt}`; `401 INVALID_CREDENTIALS`; `403 ACCOUNT_NOT_READY`; `423 ACCOUNT_LOCKED`; `428 CAPTCHA_REQUIRED`; `503 LOGIN_UNAVAILABLE` |
| `POST /api/ns/v1/login/captcha` | app via BFF, no session | `200 {captchaId, image (base64 PNG), expiresAt}` — same shape for unknown names |
| `POST /api/v1/logout` | app, `Authorization: Bearer k1.<43>` (ACTIVE or restricted) | `204`; `401 SESSION_REQUIRED` |
| `POST /api/v1/trusted-device/init` | app, restricted session | `200 {status:"KEY_EXCHANGE", enrollmentId, serverPublicJwk, challenge (JWE to the device key), expiresAt}`; `400 DEVICE_KEY_REQUIRED`; `409 STATE_CONFLICT` (ACTIVE session or init already done) |
| `POST /api/v1/trusted-device/verify` | app, restricted session | `200 {status:"MFA_REQUIRED", mfaTransactionId, expiresAt}`; `401 WRONG_CHALLENGE` + detail `attemptsLeft`; `403 NO_USABLE_FACTOR`; `409 STATE_CONFLICT`; `503` |
| `POST /api/v1/trusted-device/confirm` | app, restricted session | `201 {tokenEnvelope, status:"ACTIVE", idleExpiresAt, absoluteExpiresAt}` sealed to the key sent at confirm; `409 MFA_NOT_PASSED`; `401 MFA_FAILED`; `401 MFA_EXPIRED`; `400 REQUEST_REJECTED`; `409 STATE_CONFLICT`; `503` |
| `POST /api/v1/trusted-device/request` | new device, restricted session | `200 {status:"WAITING_APPROVAL", enrollmentId, expiresAt}` (same answer on repeat); `400 DEVICE_KEY_REQUIRED`; `409 TOO_MANY_PENDING_DEVICES`; `409 STATE_CONFLICT` |
| `GET /api/v1/trusted-device/status` | new device, restricted session | `200 {status, enrollmentId, expiresAt}` — `WAITING_APPROVAL`, `WAITING_AUTHORIZATION`, `FAILED`, `EXPIRED`; `409 STATE_CONFLICT` without a request |
| `GET /api/v1/trusted-device/pending` | primary device, ACTIVE session | `200 [{enrollmentId, deviceId (masked), platform, status, expiresAt}]`; `403 NOT_PRIMARY_DEVICE` |
| `POST /api/v1/trusted-device/pending/{enrollmentId}/approve` | primary device | `200 {status:"MFA_REQUIRED", mfaTransactionId, expiresAt}` (FACE + OTP at MFA); `403 NOT_PRIMARY_DEVICE`; `403 NO_USABLE_FACTOR`; `409 STATE_CONFLICT` |
| `POST /api/v1/trusted-device/pending/{enrollmentId}/authorize` | primary device | `200 {status:"WAITING_AUTHORIZATION", enrollmentId, authorizationToken, expiresAt}` — the QR; `409 MFA_NOT_PASSED`; `401 MFA_FAILED`; `401 MFA_EXPIRED`; `400 REQUEST_REJECTED`; `409 STATE_CONFLICT` |
| `POST /api/v1/trusted-device/claim` | new device, the same restricted session | `201 {tokenEnvelope, status:"ACTIVE", idleExpiresAt, absoluteExpiresAt}` sealed to the key sent at claim; `401 WRONG_AUTHORIZATION` + detail `attemptsLeft`; `401 AUTHORIZATION_EXPIRED`; `409 STATE_CONFLICT` |
| `GET /api/v1/devices` | app, ACTIVE session | `200 [{deviceId (masked), platform, status, trustLevel, primary, trustedAt, expiresAt, lastLoginAt}]`; `403 DEVICE_TRUST_REQUIRED` from a restricted session |
| `POST /internal/v1/customers/{customerId}/password-unlock` | bank tooling | `204`; `404 CUSTOMER_UNKNOWN` |
| `POST /internal/v1/sessions/extend` | BFF after admission (flow 16) | `200 {idleExpiresAt, absoluteExpiresAt}`; `400`; `410 SESSION_GONE`; `409 SESSION_CONFLICT`; `503` |

The token is `k1.<43 base64url>` and reaches the app only inside a compact JWE (`ECDH-ES`/`A256GCM`
to the P-256 `tokenEncryptionKey` the app sent). Valkey holds `session:v1:k1:<HMAC(token)>` with
`customerId, sessionId, deviceId?, status, channel`, deadlines and `sessionVersion`; idle 15 min
slides on extend, absolute 20 min never moves. The password is verified by Keycloak Direct Grant
(client secret) and the KC-signed ID token is checked against the realm JWKS.

**Trusted device (phase 3):** a MOBILE login carries `deviceId` + `platform` (+ optional P-256
`devicePublicKey`). The first device of a customer on a channel is trusted and made primary directly
on its first successful login (180 days, max 5 live devices). Any other device — new, trusted but not
primary, or expired — gets `status: NEED_TRUSTED_DEVICE`: a restricted Valkey session (10 min, no
absolute, never extended) that may only log out or run the trust flow below. WEB logins have
no device trust. The device ID is stored only as an HMAC lookup and an AES-GCM ciphertext, each with
its key ID (`auth.device.*`).

**Device enrollment (phase 4, DD 20 §4):** from a restricted session the app calls `init` with its
P-256 device key (a known device may send `{}` and keep the stored key); Auth answers with a fresh
server key Ksrv and a 32-byte challenge sealed to the device key. The app opens it and re-seals
`{enrollmentId, challenge}` to Ksrv for `verify` (3 attempts, counted before the check; the last
wrong answer fails the enrollment and ends the session), which opens a FACE transaction at the MFA
service. `confirm` reads the signed receipt (ES256 from a pinned key, exact claim set) and on PASSED
writes, in one SQL transaction, the new trusted row (replacing a previous row of the same
installation, expiring the oldest beyond the cap), the primary row (`FACE_CONFIRMED`), the
enrollment `COMPLETED` and the audit trail; the restricted session is consumed and a new ACTIVE
session is sealed to the key sent at confirm. Ksrv's private key lives only in the restricted
session's Valkey HASH. The MFA contract is an assumption until the MFA team confirms it.

**Approval by the primary device (phase 4, second path, slice 6):** a new installation on a restricted
session calls `request` with its public key; Auth keeps a `PENDING` device row (not trusted, at most 3
waiting per customer and channel) and an approval request bound to that session. The customer opens the
current primary device, lists the pending requests, approves one (FACE + OTP at the MFA service) and
receives a one-time 32-byte token, valid 180 s, which the app shows as a QR. The new device scans it and
calls `claim` from the same session: attempts are counted before the digest check (5, then the request
fails and the session ends), and on success one SQL transaction makes the pending row trusted and the
customer's primary (`PRIMARY_MODE = OLD_DEVICE_APPROVAL`), expires the oldest device beyond the cap,
completes the request and writes the audit trail with the approving device as actor. The old primary
stays trusted. Auth stores only the token's SHA-256. Push notification to the primary is a follow-up.

**Lockout (phase 2):** consecutive password failures on one identity escalate — after 2 the next
login must carry a solved CAPTCHA (`captcha{captchaId, answer}` from `/login/captcha`, bound to the
customer, single use, 5 min), at 3 the account is locked 15 min, at 4 for 24 h, at 5 permanently
until `password-unlock`. Only a successful login resets the count; an expired lock does not. A locked
account is answered from the database without calling Keycloak; an unknown user name is never counted.
Settings: `auth.login.lockout.{captcha-after, temporary-locks, permanent-at, captcha-lifetime}`.

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

Last run (2026-10-26, slice 6 complete): 258 tests, 0 failures — 232 unit
(domain state machines and value objects, frozen enum codes, services with in-memory doubles incl. the
approval flow, web/persistence/partner mappers, Valkey key vector and codec, error catalogue, Keycloak
admin + Direct Grant with a test-signed ID token, JWE sealer and challenge sealer round trips, MFA HTTP
adapter with test-signed FACE and FACE+OTP receipts, lockout escalation, CAPTCHA generator/service,
`@WebMvcTest` slices incl. the session filter, the trusted-device and approval routes, configuration,
12 ArchUnit rules) and 26 on Testcontainers (`RegistrationPersistenceAdapterIT`,
`CustomerAuthenticationPersistenceAdapterIT`, `TrustedDevicePersistenceAdapterIT` incl. pending rows and
`DeviceEnrollmentPersistenceAdapterIT` incl. the approval round trip on MySQL 8.4, `ValkeySessionAdapterIT`
and `ValkeyCaptchaStoreIT` on `valkey/valkey:9.1`, `ApplicationBootIT` booting everything against MySQL +
Valkey: register → 2 failures → CAPTCHA → login → decrypt envelope → extend → logout → lock → unlock →
second device NEED_TRUSTED_DEVICE → device list → tablet enrollment init → verify → confirm → ACTIVE →
watch request → tablet pending/approve/authorize (MFA mocked) → wrong QR token → claim → watch primary,
three devices). No real Customer, Keycloak, Notification or MFA service was called.

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
| `AUTH_DEVICE_LOOKUP_HMAC_KEY_D1_BASE64`, `AUTH_DEVICE_ENCRYPTION_KEY_E1_BASE64` | ≥32-byte keys protecting the stored device ID (`d1` lookup HMAC, `e1` AES-256-GCM) |

Timeouts default to 3 s per partner; no call is retried.
