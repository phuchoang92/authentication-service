# Slice 5 — device enrollment: init → verify → confirm (DB phase 4)

Status: **approved 2026-10-25, in progress** (turn 1 running). Schema: `phase-4-enrollment.sql`
(`TRUSTED_DEVICE_ENROLLMENT`; `PRIMARY_ENROLLMENT_ID`, `FACE_AUTHENTICATED`, `PRIMARY_MODE` on the
primary row; `ENROLLMENT_ID` on audit). Flow: DD 20 §4 (settled), MFA contract DD 20 §5 (proposed,
implemented behind a port), wire details DD 20 §6a where not contradicted below.

## Decisions (2026-10-25)

| Topic | Decision |
|---|---|
| Model | DD 20 init → verify → confirm with FACE. The old-device-approval columns (`AUTHORIZATION_*`, `REQUESTER_*`) stay NULL/unused in this slice |
| Who may start | only a **restricted** `NEED_TRUSTED_DEVICE` session (new device, trusted-not-primary, or expired device). An ACTIVE session gets `409 STATE_CONFLICT` |
| Routes | `POST /api/v1/trusted-device/init`, `/verify`, `/confirm` — `Authorization: Bearer <restricted token>`; no BFF JWT yet (same as every other route). `SessionFilter` already admits this prefix for restricted sessions |
| MFA | `MfaTransactionPort` (create / check) per DD 20 §5; `HttpMfaTransactionAdapter` for `POST {mfa}/internal/v1/transactions` and `POST …/{id}/check`, receipt = compact ES256 JWS verified against a **pinned** public key, exact claim set; `MockRestServiceServer` tests. Real MFA wired when the team confirms |
| Ksrv | P-256 pair generated at init, kept **only** in the restricted session (Valkey, encrypted-at-rest is out of scope), used at verify, dropped at confirm/expiry. Persisting it for Smart OTP is phase 5 |
| Device key | new device: `devicePublicJwk` is required at init; known device with a stored key: `{}` and the stored key is used (DD 20 "keep the old key"); known device sending a **different** key → treated as reinstall: allowed, the new key replaces the old one only on confirm PASSED |
| Verify attempts | 3 per enrollment (configurable 1–10), counted before the check; the last wrong answer fails the enrollment and ends the restricted session |
| Order | init → verify → confirm, each step once; out of order → `409 STATE_CONFLICT` |
| Confirm outcomes | `PASSED` → trust; `PENDING` → `409 MFA_NOT_PASSED` keep session; `FAILED` → fail enrollment, end session, `401 MFA_FAILED`; `EXPIRED`/404 → `401 MFA_EXPIRED`, end session; bad signature/claims → `400 REQUEST_REJECTED` + security log, no state change; MFA 5xx/timeout → `503`, nothing changes |
| Trust commit (one SQL transaction) | device row: existing live row of this installation → `EXPIRED` (replaced) and a new `ACTIVE`/`TRUSTED` row with the confirmed key; cap: expire oldest by last login beyond 5; `PRIMARY_TRUSTED_DEVICE` → this device, `PRIMARY_ENROLLMENT_ID`, `FACE_AUTHENTICATED=1`, `PRIMARY_MODE=FACE_CONFIRMED`; enrollment `COMPLETED`; audit events 0..n (`DEVICE_TRUSTED`/`DEVICE_RETRUSTED`, `PRIMARY_CHANGED`, `DEVICE_EXPIRED`…) with `ENROLLMENT_ID` and the SHA-256 of the MFA receipt in `METADATA` |
| After commit | end the restricted session, issue a new **ACTIVE** session sealed to the `tokenEncryptionKey` the app sent at **confirm** (DD 20 §6a open point 1: the trusted flow uses its own key, not the login one) |
| Old primary | stays trusted (DD 20 §7); biometric revocation does not exist yet |
| Phase-3 direct path | now also writes `PRIMARY_MODE=DIRECT_PRIMARY`, `FACE_AUTHENTICATED=0` |

Proposed value lists: `PURPOSE` = `TRUST_DEVICE`; `STATE` = `KEY_EXCHANGE` (after init), `MFA_REQUIRED`
(after verify), `COMPLETED`, `FAILED`, `EXPIRED`; `PRIMARY_MODE` = `DIRECT_PRIMARY`, `FACE_CONFIRMED`
(`OLD_DEVICE_APPROVAL` reserved); `CONFIRMED_MFA_METHOD` = `FACE`; `CREATION_IDEMPOTENCY_DIGEST` =
HMAC(session lookup digest ‖ device lookup) so a repeated init from the same restricted session returns
the same enrollment; `EXPIRES_AT` = restricted session expiry.

Deferred: BFF assertion, Kreq/DPoP, Ksrv persistence (phase 5), biometric revocation (phase 6/7),
Customer status re-read before the ACTIVE session (phase 9), old-device approval.

## API (envelope + codes as everywhere)

| Step | Request | 200 | Errors |
|---|---|---|---|
| `init` | `{devicePublicJwk?: JWK}` | `{status:"KEY_EXCHANGE", enrollmentId, serverPublicJwk, challenge:<compact JWE to device key, typ trusted-device-challenge+jwe>, expiresAt}` | `400 REQUEST_REJECTED` (new device without key / bad JWK), `409 STATE_CONFLICT` |
| `verify` | `{challengeResponse:<compact JWE to Ksrv, typ trusted-device-challenge-response+jwe>}` | `{status:"MFA_REQUIRED", mfaTransactionId, expiresAt}` | `401 WRONG_CHALLENGE` (+`attemptsLeft` detail), `403 NO_USABLE_FACTOR`, `409 STATE_CONFLICT`, `503` |
| `confirm` | `{tokenEncryptionKey: JWK}` | `201 {tokenEnvelope, status:"ACTIVE", idleExpiresAt, absoluteExpiresAt}` | `409 MFA_NOT_PASSED`, `401 MFA_FAILED`, `401 MFA_EXPIRED`, `409 STATE_CONFLICT`, `503` |

Challenge = 32 random bytes; the session stores only its SHA-256. The challenge JWE payload is
`{challenge, enrollmentId}`; the response JWE payload must echo both.

## Code (role packages, infrastructure parent)

- `domain.model`: `DeviceEnrollment` aggregate (id, customerId, channel, deviceId, purpose, state,
  targetDeviceId?, mfaTransactionId?, attempts, expiresAt, version; `markKeyExchanged`, `markMfaRequired(mfaId)`,
  `complete()`, `fail()`, `nextAttempt(max)`), `EnrollmentState`, `EnrollmentPurpose`, `PrimaryMode`,
  `EnrollmentId`, `EnrollmentPolicy` (maxVerifyAttempts); `TrustedDevice.retrust(newKey, now, policy)`;
  `Session` gains `enrollmentId`, `serverKeyJwk` (private, redacted), `deviceKeyJwk`, `challengeDigest`
  as restricted-session fields (stored in the Valkey HASH; never in SQL).
- `application.command`: `InitEnrollmentCommand`, `VerifyEnrollmentCommand`, `ConfirmEnrollmentCommand`.
- `application.result`: `InitEnrollmentResult` (KeyExchange | Conflict | Unavailable), `VerifyEnrollmentResult`
  (MfaRequired | WrongChallenge(attemptsLeft) | NoUsableFactor | Conflict | Unavailable),
  `ConfirmEnrollmentResult` (Trusted(envelope, deadlines) | MfaPending | MfaFailed | MfaExpired | Rejected | Conflict | Unavailable).
- `application.port.in`: `InitEnrollmentUseCase`, `VerifyEnrollmentUseCase`, `ConfirmEnrollmentUseCase`.
- `application.port.out.repository`: `EnrollmentRepository` (`create(DeviceEnrollment)` idempotent on `UQ_DE_CREATION`,
  `find(id, customerId)`, `saveIfCurrent`); `TrustedDeviceRepository.trustConfirmed(TrustConfirmation)` — the
  one-transaction commit (device rows, primary, enrollment COMPLETED, audit); `SessionStore` unchanged (restricted
  fields travel in `Session`).
- `application.port.out.gateway`: `MfaTransactionPort` (`create(MfaTransactionRequest) → Created | NoUsableFactor`,
  `check(mfaTransactionId, authOperationId, contextDigest) → Passed(receiptDigest) | Pending | Failed | Expired | Rejected`),
  `ServerKeyPairGenerator` (P-256), `ChallengeSealer` (seal to device key / open with Ksrv — Nimbus, like the token
  envelope). `port.out.model`: `MfaTransactionRequest`, `TrustConfirmation`.
- `application.service`: `DeviceEnrollmentService` (the three use cases; owns the restricted-session reads/writes
  and calls `TrustedDeviceService.confirmTrust(...)` for the device rules — Login → TrustedDevice → nothing back).
- Adapters: `infrastructure.adapter.out.mfa` (`HttpMfaTransactionAdapter`, `dto`, `mapper`, `MfaReceiptVerifier`),
  `infrastructure.adapter.out.jose` (`NimbusChallengeSealer`, `NimbusServerKeyPairGenerator`),
  persistence (`DeviceEnrollmentEntity`, repository, mapper; `TrustedDevicePersistenceAdapter.trustConfirmed`;
  `PrimaryTrustedDeviceEntity` new columns), `SessionHashCodec` new optional fields,
  REST `TrustedDeviceController` + `dto` + `TrustedDeviceRestMapper`, codes `STATE_CONFLICT`, `WRONG_CHALLENGE`,
  `NO_USABLE_FACTOR`, `MFA_NOT_PASSED`, `MFA_FAILED`, `MFA_EXPIRED` vi/en.
- `infrastructure.config`: `MfaProperties` (origin, timeout, receipt public JWK, pinned `kid`), `EnrollmentProperties`
  (max attempts); wiring in `LoginConfiguration` (flag `auth.login.enabled`).
- Flyway `V4__enrollment.sql` = phase file.

## Tests

`DeviceEnrollmentTest`, `DeviceEnrollmentServiceTest` (order, attempts, each MFA outcome, reinstall key replacement,
old primary stays trusted), `HttpMfaTransactionAdapterTest` (create 201/200/409/422/5xx, check with a test-signed
receipt: PASSED, wrong key, wrong claims, PENDING, 404), `NimbusChallengeSealerTest` (round trip, wrong key),
persistence IT (`UQ_DE_CREATION` idempotency, confirmed-trust transaction incl. replace + primary + audit sequence),
`SessionHashCodecTest` new fields, `@WebMvcTest` for the three routes (restricted token required; ACTIVE → 409),
boot IT: second device → init → verify → (MFA mocked PASSED) → confirm → ACTIVE token, device list shows two
devices with the new primary.

## Turns

1. Domain + application (aggregate, commands/results, use cases, `DeviceEnrollmentService`, `TrustedDeviceService.confirmTrust`,
   in-memory doubles) + codes; `mvn -o test`.
2. Out adapters: MFA HTTP + receipt verifier, Nimbus challenge sealer/key pair, V4 + enrollment persistence +
   confirmed-trust transaction, session codec fields; ITs.
3. REST + config + boot IT + README/ARCHITECTURE/plan status; `mvn -o clean verify`.
