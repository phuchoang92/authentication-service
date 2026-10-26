# Slice 6 — a new device trusted and made primary by the current primary device (DB phase 4, approval path)

Status: **implemented 2026-10-26** (turns 1–3; see README for the test run). Schema: the phase-4 columns
(`REQUESTER_*`, `ACTOR_DEVICE_ID`, `AUTHORIZATION_*`, `PRIMARY_MODE = OLD_DEVICE_APPROVAL`) already in
`V4__enrollment.sql`; no new migration. Slice 5 is the **primary enrollment** (`init → verify → confirm`,
FACE on the device itself); this slice is the second path of DD 20 §4 / phase 4.

## Decisions (2026-10-26)

| Topic | Decision |
|---|---|
| Outcome | the approved device becomes **trusted and primary instantly** (`PRIMARY_MODE = OLD_DEVICE_APPROVAL`, `FACE_AUTHENTICATED = 0`); the old primary stays trusted |
| Approver MFA | **FACE + OTP** at the MFA service, on the primary device, before the token is issued |
| Requester MFA | none; the one-time token from the approved primary is the factor |
| Push to the primary | optional → not in this slice; the primary polls the pending list (follow-up: push token + Notification push adapter) |
| Request step | `POST /api/v1/trusted-device/request` from the restricted session; the device's public JWK and platform are **stored** on a PENDING device row, no challenge and no Ksrv in this path |
| Known installation | a live row of the same installation (trusted-not-primary) is reused as the target and keeps its stored key and platform |
| Limits | token lifetime 180 s, 5 claim attempts, max 3 pending installations per customer + channel, pending window = restricted session (10 min), trust 180 days |
| Binding | the claim and the status poll are bound to the restricted session that made the request (`CREATION_IDEMPOTENCY_DIGEST`) |
| Token | 32 random bytes, base64url; Auth stores only its SHA-256 digest, expiry and claim count |
| MFA contract | `MfaTransactionRequest` carries `purpose` and `factors`; the receipt's `purpose` claim equals the enrollment purpose and its `factor` claim equals the factors joined with `+` (`FACE`, `FACE+OTP`) — **assumption** until the MFA team confirms |

## Flow

```
watch   POST /api/ns/v1/login ............................. 201 NEED_TRUSTED_DEVICE (restricted token R)
watch   POST /api/v1/trusted-device/request {devicePublicJwk, platform} → 200 {status: WAITING_APPROVAL, enrollmentId, expiresAt}
watch   GET  /api/v1/trusted-device/status ................ 200 {status, enrollmentId, expiresAt}          (poll)
phone   GET  /api/v1/trusted-device/pending ............... 200 [{enrollmentId, deviceId (masked), platform, status, expiresAt}]
phone   POST /api/v1/trusted-device/pending/{id}/approve .. 200 {status: MFA_REQUIRED, mfaTransactionId, expiresAt}
phone   POST /api/v1/trusted-device/pending/{id}/authorize  200 {status: WAITING_AUTHORIZATION, enrollmentId, authorizationToken, expiresAt}  → QR
watch   POST /api/v1/trusted-device/claim {authorizationToken, tokenEncryptionKey} → 201 {tokenEnvelope, status: ACTIVE, idleExpiresAt, absoluteExpiresAt}
```

Status table: `409 STATE_CONFLICT` (wrong session kind, other path in progress, out of order, another approver),
`400 DEVICE_KEY_REQUIRED`, `409 TOO_MANY_PENDING_DEVICES`, `403 NOT_PRIMARY_DEVICE`, MFA outcomes as in slice 5
(`409 MFA_NOT_PASSED`, `401 MFA_FAILED`, `401 MFA_EXPIRED`, `400 REQUEST_REJECTED`, `403 NO_USABLE_FACTOR`),
`401 WRONG_AUTHORIZATION` + detail `attemptsLeft` (0 = failed, session ended), `401 AUTHORIZATION_EXPIRED`
(enrollment EXPIRED, session ended), `503` on repository/MFA failure.

## Code

- `domain.enums`: `EnrollmentPurpose.TRUST_DEVICE_APPROVAL`; `EnrollmentState.WAITING_APPROVAL`, `WAITING_AUTHORIZATION`; `MfaFactor`.
- `domain.model`: `TrustedDevice.pending(...)`, `trustByApproval(now, policy)`, `isPending()`; `DeviceEnrollment` gains
  `actorDeviceId`, `mfaMethod`, `authorizationTokenDigest`, `authorizationExpiresAt`, `authorizationAttempts`,
  `authorizationConsumedAt` with `requestApproval`, `approveBy`, `authorize`, `countClaimAttempt`, `consumeAuthorization`;
  `EnrollmentPolicy(maxVerifyAttempts, pendingWindow, approvalTokenLifetime, maxClaimAttempts, maxPendingDevices)`.
- `application`: commands `RequestApproval`, `ApprovalStatus`, `ListPendingDevices`, `ApproveEnrollment`,
  `AuthorizeEnrollment`, `ClaimEnrollment`; matching results and use cases; `DeviceApprovalService`;
  `TrustedDeviceService.registerPendingDevice / primaryDeviceId / confirmTrustByApproval`; shared `EnrollmentDigests`;
  ports `TrustedDeviceRepository.registerPending / countPending`, `EnrollmentRepository.findBySession / findApproval /
  findOpenApprovals`, `AuthorizationTokenGenerator`; `MfaTransactionRequest(purpose, factors)`, `MfaCheckRequest`;
  `TrustConfirmation(primaryMode, faceAuthenticated, actorDeviceId, receiptDigest?)`.
- Persistence (turn 2): entity columns, pending rows, approval lookups, the generalised trust commit, ITs.
- REST + config + boot IT + docs (turn 3).

## Turns

1. Domain + application + MFA port generalisation + in-memory doubles + unit tests; `mvn -o test`.
2. Persistence: `DeviceEnrollmentEntity` phase-4 columns, `registerPending`/`countPending`, approval lookups,
   `trustConfirmed` for a PENDING row moved to trusted; ITs; `mvn -o verify`.
3. REST (`DeviceApprovalController`, `DeviceApprovalRestMapper`, DTOs with opaque string IDs per CODE_CONVENTIONS §5),
   codes vi/en, config, boot IT, README/ARCHITECTURE; `mvn -o clean verify`.
