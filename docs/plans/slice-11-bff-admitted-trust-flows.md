# Slice 11 — trusted-device routes behind BFF admission, primary trust transaction in the cache

## Context

- The BFF already checks the app's session token, its status and its deadlines before it forwards a request.
  The trust flows read the session again (`findRestricted` / `findActive`) to learn who calls and what kind of
  session it is.
- The restricted session's Valkey HASH also carries the primary enrollment's transaction (Ksrv, challenge
  digest, `keyProven`), and deleting that session is the "only one confirm commits" guard. One record does
  three jobs.

## Decisions (2026-11-03)

| Topic | Decision |
|---|---|
| Caller identity | The BFF calls `/api/v1/trusted-device/**` with exactly one `Authorization: Bearer <assertion>` (DD 20 §6a): ES256, pinned key, `typ=bff-assertion+jwt`, header names the key, no `jwk`/`jku`/`x5u`/`x5c`/`crit`; claims exactly `iss, aud, sub, sid, channel, deviceId, sessionKind, iat, exp, jti`; `aud=authentication-service`; lifetime ≤ 60 s; 5 s skew. `sub` (customer number) and `sessionKind` (`ACTIVE` / `NEED_TRUSTED_DEVICE`) are added to §6a's set; `sid` is the session UUID of this tree. |
| Replay | `jti` used once: Valkey `SET NX` on `bff-assertion:used:v1:<SHA-256(jti)>` until `exp + 5 s`. Bad or replayed assertion → `401 REQUEST_REJECTED`; store unavailable → `503 TEMPORARILY_UNAVAILABLE`. |
| Kind per route | Auth still checks the kind the BFF asserted, per route, with no I/O: new-device routes (`request`, `status`, `claim`, `init`, `verify`, `confirm`) need `NEED_TRUSTED_DEVICE` (otherwise `409 STATE_CONFLICT`); primary routes (`pending`, `approve`, `authorize`) need `ACTIVE` and the trusted primary device (otherwise `403 NOT_PRIMARY_DEVICE`). |
| Other routes | Logout, `/api/v1/devices` and extend keep the session token (`SessionFilter`) in this slice. |
| Old-device approval | `approve` / `authorize` keep the database (`TRUSTED_DEVICE_ENROLLMENT`) as today (user decision 2026-11-03). The new device's `request` keeps writing its row. |
| Primary transaction | `init → verify → confirm` moves into its own Valkey record (turns 2–3); one-shot confirm becomes a CAS on that record; the enrollment row is written once, in the trust commit. |

## Turns

1. **Done 2026-11-03.** Admission gate and commands: `AdmittedSession` (domain), `BffAssertionVerifier`,
   `BffAssertionFilter`, `AssertionReplayGuard` + `ValkeyAssertionReplayStore`, `BffProperties`
   (`auth.bff.assertion-issuer`, `auth.bff.assertion-public-jwk`, no default); nine trust commands carry the
   admitted session instead of the token; `SessionService` loses `findRestricted` / `findActive`, gains
   `findLive(SessionLookup)`, and `consume` / `end` take a `SessionLookup`. `DeviceApprovalService` reads no
   session; a request's deadline is `now + pendingWindow` (the PENDING row's). `DeviceEnrollmentService`
   still reads the restricted session by its asserted address, only for the transaction context it holds.
   `mvn -o verify`: 270 unit tests, 31 ITs.
2. **Done 2026-11-03.** `EnrollmentTransaction` (domain): owner (customer, channel, device, the restricted
   session that ran init), device key and platform, Ksrv pair, challenge digest, verify attempts, MFA transaction
   ID, deadline, version; states KEY_EXCHANGE → MFA_REQUIRED only (it reuses `EnrollmentState`); failure, expiry
   and the trust commit remove it. Port `EnrollmentTransactionStore` (`createIfAbsent`, `find`, `saveIfCurrent`,
   `deleteIfCurrent`) and `ValkeyEnrollmentTransactionAdapter`: one HASH per device at
   `enrollment-tx:v1:<channel>:<customerId>:<deviceId>`, `PEXPIREAT` = deadline, every write WATCH/compare
   version/MULTI, a save replaces the whole HASH (`DEL` + `HSET`). The confirm one-shot is `deleteIfCurrent`
   (CAS removal), replacing today's session `DEL`. Ksrv's private key stays unencrypted, as in the session today.
   Not wired into the services yet. `mvn -o verify`: 280 unit tests, 36 ITs.
3. **Done 2026-11-03 (decisions agreed the same day).** `DeviceEnrollmentService` runs on
   `EnrollmentTransactionStore` and reads no session: init creates the transaction (deadline = restricted
   session TTL, `auth.device.restricted-session-ttl`); init from the same session twice is `409`, init from a later
   login of the same device removes the earlier transaction (CAS) and starts over; verify and confirm need the
   transaction of this session, open and at their step. Wrong-answer exhaustion, no usable factor, MFA FAILED and
   EXPIRED remove the transaction and end the restricted session (no FAILED/EXPIRED row is written any more).
   PASSED: `deleteIfCurrent` (one-shot) → consume the restricted session (already gone → `409`) → trust commit,
   which **inserts** the enrollment row already COMPLETED (`TrustConfirmation.creationSessionId`,
   `DeviceEnrollment.fromTransaction`). `MfaCheckRequest` carries the customer; `HttpMfaTransactionAdapter` lost its
   row-based `CustomerLookup`. `EnrollmentDigests.contextDigest(EnrollmentTransaction)` gives the same digest as
   the row would. `EnrollmentContext` left `Session` and the session codec (a HASH written by slice 5 with those
   fields no longer decodes; restricted sessions live 10 minutes). Fixed a turn-1 regression: `request` again
   refuses a session whose primary enrollment is in flight. `SessionService.findLive(SessionLookup)` (turn 1)
   was removed, unused. `mvn -o verify`: 286 unit tests, 36 ITs.
4. `request / status / claim` bound to the device instead of the restricted session (one open request per device).
5. Clean-up: unused result variants (`SessionGone` of the nine trust routes), `EnrollmentRepository.find` (no
   caller since turn 3), docs.

## Not in this slice

- The BFF does not mint these assertions yet (`mobile-bff` has no Auth admission code). Until it does, the
  trusted-device routes are reachable only by a caller holding the BFF key (tests).
- mTLS / workload identity between BFF and Auth, and BFF key rotation (one pinned key now).
