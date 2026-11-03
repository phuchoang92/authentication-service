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
2. `TrustTransactionStore` (port + Valkey adapter, HASH codec, CAS on the step) and the domain transaction.
3. `init / verify / confirm` on the transaction record; the enrollment row only at commit; `EnrollmentContext`
   leaves `Session` and the session codec.
4. `request / status / claim` bound to the device instead of the restricted session (one open request per device).
5. Clean-up: unused result variants (`SessionGone` where no session is read any more), docs.

## Not in this slice

- The BFF does not mint these assertions yet (`mobile-bff` has no Auth admission code). Until it does, the
  trusted-device routes are reachable only by a caller holding the BFF key (tests).
- mTLS / workload identity between BFF and Auth, and BFF key rotation (one pinned key now).
