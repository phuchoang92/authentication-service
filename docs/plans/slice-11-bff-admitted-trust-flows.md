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
| Old-device approval | `approve` / `authorize` keep the database (`TRUSTED_DEVICE_ENROLLMENT`) as today (user decision 2026-11-03). The new device's `request` keeps writing its row. The request belongs to the device and waits 24 h (agreed 2026-11-03). |
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
4. **Done 2026-11-03.** `request / status / claim` are bound to the device, not to the restricted session that
   made the request: `EnrollmentRepository.findBySession` became `findLatestApproval(customer, channel, device)`
   (the newest approval row whose requester lookup is this device, any state, so `status` still reports
   FAILED/EXPIRED). `request` answers with the device's open request when there is one, from this login or a later
   one (one open request per device); a closed request lets a later login ask again, while the same login still
   gets `409` (`UQ_DE_CREATION` stays per session). `claim` works from any restricted session of the device. The
   approval window (`auth.login.approval.pending-window`, also the PENDING row's lifetime) went from 10 minutes to
   **24 hours**, so the new device can log in again to poll and claim. Known limits: two simultaneous requests from
   two logins of one device can still make two rows (no database guard per device); a request written under a
   rotated-out lookup key is not found; the claim's audit events use the claiming session as correlation ID
   (linked to the request by `ENROLLMENT_ID`). `mvn -o verify`: 288 unit tests, 37 ITs.
5. **Done 2026-11-03.** Clean-up of what slice 11 left unused: the `SessionGone` variant of the nine trust
   results and its `401 SESSION_REQUIRED` mapping (a missing or bad caller is now the filter's `401
   REQUEST_REJECTED`; `ListDevicesResult.SessionGone` stays, `/api/v1/devices` still reads the session);
   `EnrollmentRepository.find` and the adapter's `isTargetDevice`; `DeviceEnrollment.start`, `countAttempt`,
   `attemptsExhausted`, `markMfaRequired` (the primary steps live on `EnrollmentTransaction`, its row is made by
   `fromTransaction`). Tests that used them now use approval rows or `fromTransaction`. README route table updated.
   `mvn -o verify`: 288 unit tests, 37 ITs.

6. **Done 2026-11-04.** One generic cache transaction store replaces the enrollment-only one (turn 2):
   port `TransactionStore` over `CacheTransaction<P>` (kind, id, deadline, version, payload) with the same four
   CAS operations; `ValkeyTransactionAdapter` keeps one HASH per transaction at `tx:v1:<purpose>:<id>`
   (`TransactionKeys`), the payload as one strict JSON field (`TransactionHashCodec`). The enrollment is now a
   pure payload (no deadline or version of its own) at `tx:v1:enrollment:<channel>:<customerId>:<deviceId>`.
   `EnrollmentTransactions` is the enrollment's typed view of the store (`wasStartedBy`, `makeRoomFor`, `open`,
   `findOpenAt`, `update`, `claim`, `remove`), used by the three enrollment steps and by `request`'s in-flight
   check. `DeviceEnrollmentService` was split into one service per use case, `InitEnrollmentService`,
   `VerifyEnrollmentService` and `ConfirmEnrollmentService` (one bean each), written to the 2026-11-04
   method-shape rules (public step lists, `KeyExchangeStart` + `DeviceKey` input records, role names such as
   `newDeviceSession`); `FaceCheckRequests` builds the FACE create and check requests in one place so verify
   and confirm bind the same purpose, factor and context digest. Behavior unchanged; the flow test is
   `DeviceEnrollmentFlowTest`. `DeviceApprovalService` was split the same way into `RequestApprovalService`,
   `ApprovalStatusService`, `ClaimEnrollmentService` (the new device) and `ListPendingDevicesService`,
   `ApproveEnrollmentService`, `AuthorizeEnrollmentService` (the primary device), one bean each, over
   `ApprovalRequests` (the approval flow's view of `EnrollmentRepository`) and `ApprovalCheckRequests` (the FACE +
   OTP create and check requests); `TrustedDeviceService.primaryDeviceIdOf(session)` holds the "full session on
   the trusted primary" check the three primary routes share. Behavior unchanged (approve now takes the MFA
   request's customer and channel from the request row, which `findApproval` already matched to the session); the
   flow test is `DeviceApprovalFlowTest`.
   Records left by turn 2's key layout are not read; restricted sessions live 10 minutes.
   `mvn -o verify`: 336 unit tests, 37 ITs.
7. **Done 2026-11-04.** Three-parameter rule on `TrustedDeviceService`: `registerPendingDevice` (7 parameters),
   `confirmTrust` (6) and `routeAfterPassword` (5) take `RegisterPendingDeviceCommand`, `ConfirmTrustCommand`
   (with the proved `DeviceKey`) and `RouteAfterPasswordCommand` (plus the `DevicePossession` callback, which a
   command may not carry). Behavior unchanged. `mvn -o verify`: 336 unit tests, 37 ITs.
8. **Done 2026-11-04.** Three-parameter rule on the domain factories. `DeviceInstallation` (customer, channel,
   device) names what a row, a request and a session are about (`AdmittedSession.installation()`,
   `DeviceEnrollment.requester()`). `TrustedDevice.pending(NewDevice, Duration)` and
   `trustedByEnrollment(NewDevice, DevicePolicy)` replace two 8-parameter factories (`NewDevice`: ID, installation,
   presented `DeviceKey`, creation time); `DeviceEnrollment.requestApproval(ApprovalRequestStart)` replaces 6
   parameters. `TrustedDevice.trustedNow` is removed: no production code used it and its "trusted at the first
   login" no longer holds since slice 13; tests build such rows with `DomainFixtures.trustedDevice`, which may
   leave the key empty like a row from before slice 13. Behavior unchanged. `mvn -o verify`: 336 unit tests, 37 ITs.
9. **Done 2026-11-04.** Three-parameter rule on sessions. `SessionService.issueActive` / `issueRestricted` (5
   parameters each) take `IssueSessionCommand`; `LoginService` builds it once and the device routing only picks
   which of the two to call. `Session.start(NewSession, SessionPolicy)` and `startRestricted(NewSession,
   DevicePolicy)` replace two 6-parameter factories; `NewSession` keeps `deviceId` nullable (WEB has no
   installation), so it is not a `DeviceInstallation`. `SessionService` lost its wildcard import. Tests start
   sessions from `DomainFixtures.mobileSession`. Behavior unchanged. `mvn -o verify`: 336 unit tests, 37 ITs.
10. **Done 2026-11-04.** A cache transaction is opened from its kind: `TransactionKind.open(id, expiresAt,
    payload)` replaces the 4-parameter `CacheTransaction.open(kind, id, expiresAt, payload)`; the kind already
    carries the payload type. Behavior unchanged. `mvn -o verify`: 336 unit tests, 37 ITs.
11. **Done 2026-11-04.** Method shape in `TrustedDeviceService`: the "live, trusted now, the customer's primary"
    checks that `routeAfterPassword` and `primaryDeviceId` each repeated are one private step,
    `findTrustedPrimary(DeviceInstallation, now)`; the 3-parameter `primaryDeviceId` is gone (`primaryDeviceIdOf`
    was its only caller). `confirmTrustByApproval` names its lookup `findApprovedRow`. Every method is 22 lines or
    fewer. `RouteAfterPasswordCommand` now refuses a MOBILE login without an installation, as `LoginCommand`
    already did. Behavior unchanged. `mvn -o verify`: 336 unit tests, 37 ITs.
12. **Done 2026-11-04.** R02 on `domain`: the 96 `Objects.requireNonNull(x, "x")` checks became Lombok `@NonNull`
    on the record component or parameter (30 files; 5 compact constructors that held only null checks are gone);
    a record header now shows at a glance which components may be null. One check stays: `trustByApproval`
    checks the row's own `publicKey`, which is a field, not a parameter. Where a state check came first
    (`approveBy`, `authorize`, `markMfaRequired`, `markUserCreated`) the null check now runs first, so a call in
    the wrong state with a null argument is an NPE rather than a state exception (both are programming errors).
    Lombok's NPE message is "x is marked non-null but is null". `mvn -o verify`: 336 unit tests, 37 ITs.
13. **Done 2026-11-04.** R02 on `application` (commands, results, port models, the services' own records): 111
    checks became `@NonNull`, nested records inside sealed interfaces and services included (`LoginResult`,
    `SessionService.IssuedSession`, `DeviceProofVerifier.Outcome.Proven`, ...); `InitialPasswordGenerator` takes
    `@NonNull SecureRandom`. Kept: the three conditional checks in `SecurityAuditEvent` (a field required only for
    some reasons), whose messages `SecurityAuditEventTest` asserts. No check moved behind or before another
    statement. `mvn -o verify`: 336 unit tests, 37 ITs.
14. **Done 2026-11-05.** R02 on `infrastructure`: 35 checks became `@NonNull`, including the expression form in bean
    constructors (`this.x = Objects.requireNonNull(x, "x")`, `Map.copyOf(Objects.requireNonNull(...))`,
    `Objects.requireNonNull(baseUrl).replaceAll(...)` in `KeycloakAdminAdapter`), which now read as plain
    assignments with the check on the parameter. `TransactionHashCodec`, whose constructor only assigned its one
    field, is `@RequiredArgsConstructor`; the others keep explicit constructors because they validate or derive a
    field. Kept: `DeviceIdProtection`'s two checks whose message names the key purpose. Across `src/main` six
    `requireNonNull` remain, each with a reason (a field rather than a parameter, a condition, or a message that
    says more than the name). `mvn -o verify`: 336 unit tests, 37 ITs.
15. **Done 2026-11-06.** Valkey connection pool. Measured first: every compare-and-set (`WATCH … EXEC`, used by the
    session, CAPTCHA and transaction adapters) ran on a dedicated connection that Spring opened and closed per
    write, because no pool was configured: 4 new TCP connections and 40 commands per enrollment flow, p50 about
    11 ms on a local Valkey 9.1.2, and connection failures after about 10 000 writes in a row. `commons-pool2` plus
    `spring.data.redis.lettuce.pool` (`AUTH_VALKEY_POOL_SIZE` 32, `AUTH_VALKEY_POOL_MAX_WAIT` PT0.25S) keeps those
    connections open: 0 new connections, 28 commands, p50 about 5 ms. One pooled connection is the shared one for
    ordinary commands. A write that gets no connection within the wait is `RepositoryUnavailableException`, so the
    step answers "unavailable"; reads still answer. No adapter code changed. Tests: `ValkeyTransactionAdapterIT`
    (writes reuse their connection; an exhausted pool is unavailable), `ApplicationBootIT` (the application's own
    settings give the pool). Not done: one-command compare-and-set (`SET … IFEQ`, `DELIFEQ`; about 1.6 ms in the
    same measurement), which changes the record format and contract 16. `mvn -o verify`: 336 unit tests, 40 ITs.
16. **Done 2026-11-06.** One-command compare-and-set for the transaction store. A transaction is one JSON STRING
    at `tx:v2:<purpose>:<id>` (`{"schemaVersion":2,"purpose",…,"expiresAtMs",…,"version",…,"payload":{…}}`,
    `TransactionJsonCodec`, deterministic text) instead of a HASH at `tx:v1:`. `ValkeyRecordCommands` sends
    `SET … NX PXAT` (create), `SET … IFEQ <text read> PXAT` (save) and `DELIFEQ <text read>` (remove): Valkey
    compares the stored text itself, so there is no `WATCH`/`MULTI`, no Lua and no connection of its own; each
    call is one round trip. `version` still moves on with every save, so no earlier text can come back. The port
    is `saveIfCurrent(current, changedPayload)`: a write succeeds only while the store holds exactly the
    transaction the caller read (stricter than "same version"). `CacheTransaction.next` replaces
    `withPayload`/`withVersion`. Measured with the application's adapter on a local Valkey 9.1.2: 7 commands and
    about 1.8 ms per enrollment flow (11 ms before the pool, 5 ms with it). Needs Valkey 9.0 or later (`DELIFEQ`;
    Redis has `DELEX` instead, which Valkey 9.1.2 rejects); a server without the commands makes every write
    "unavailable". Lettuce 7.5.2 has no `DELIFEQ`, so the commands go out by name with their reply type.
    Contract 16 does not describe this record, so it was not changed; records at `tx:v1:` are not read (they
    lived 10 minutes). The session and CAPTCHA adapters still use `WATCH … EXEC` on the pool: their HASH layout
    is fixed by contract 16. Tests: `TransactionJsonCodecTest` (fixed text, read-back encodes to the stored text,
    the real enrollment payload, strict decoding), `ValkeyTransactionAdapterIT` (16 racing writers, one winner;
    same version with another payload is refused; a write needs no pooled connection), pool tests moved to
    `ValkeySessionAdapterIT`. `mvn -o verify`: 338 unit tests, 43 ITs.
17. **Done 2026-11-07 (DD 22 approved the same day).** The session record is one JSON STRING at
    `session:v3:<channel>:<sessionId>` (`SessionJsonCodec`: fixed property order, `secretDigest` = SHA-256 of the
    token's secret, the secret itself no longer stored) and `ValkeySessionAdapter` is one command per call on
    `ValkeyRecordCommands`: `SET … NX PXAT` at login, `GET`, `SET … IFEQ <text read> PXAT` on extend, `DEL` on
    logout; no `WATCH`, no pooled connection. `SessionStore.saveIfCurrent(StoredSession current, Session changed)`;
    `StoredSession` carries the digest. Measured on the real adapters, local Valkey 9.1.2, 2000 operations each,
    two runs (p50; before = HASH with WATCH on a pooled connection, after = one JSON STRING, no pool): create 4
    commands / 0.57 ms → 1 / 0.30 ms; read by token 1 / 0.26 ms → 1 / 0.27 ms; extend 7 / 1.25 ms → 2 / 0.51 ms
    (p99 3.0 ms → 1.65 ms); delete 1 / 0.24 ms, unchanged. The BFF (`mobile-bff` `AuthSessionAdmission`) reads the same record;
    the shared vectors `docs/DD/target/reference/session-record-vectors.json` run in both test suites (the BFF's
    `mvn verify` cannot run here: its `authentication-protocol` dependency is missing from the workspace; its two
    classes were compiled and unit-tested standalone, 15 tests). Sessions at `session:v1:` are not read: every
    session logs in again at deploy (cut over, DD 22 §8). The pool now serves only `ValkeyCaptchaStore`, whose IT
    took over the two pool tests. `mvn -o verify`: 339 unit tests, 46 ITs.
18. **Done 2026-11-07.** `ValkeyCaptchaStore` is a one-shot transaction of kind `captcha` in the shared
    `TransactionStore` (`tx:v2:captcha:<id>`, payload `CaptchaChallenge`: bound customer or null, the answer's HMAC
    from `CaptchaAnswerDigest`, formerly `CaptchaKeys`): `save` = `createIfAbsent`, `consume` = `find` +
    `deleteIfCurrent`, then the comparison; the challenge's deadline is the transaction's. With that no adapter
    uses `WATCH … EXEC` any more, so the connection pool of turn 15 (`commons-pool2`, `AUTH_VALKEY_POOL_*`) is
    removed again and `ArchitectureTest` forbids `SessionCallback` in the Valkey adapters. CAPTCHA records at
    `captcha:v1:` are not read (they lived 5 minutes). Measured on the real store, local Valkey 9.1.2, 2000
    operations, two runs (p50): save 1 command / 0.22 ms, consume 2 commands (`GET`, `DELIFEQ`) / 0.46 ms; before,
    consume was `WATCH → HGETALL → MULTI → DEL → EXEC` on a pooled connection. `mvn -o verify`: 340 unit tests,
    43 ITs.
19. **Done 2026-11-08.** The company's ElastiCache offers Valkey 8.x by default (AWS: `SET … IFEQ` since 8.1,
    `DELIFEQ` only since 9.0). `ValkeyRecordCommands.deleteIfUnchanged` no longer uses `DELIFEQ`: it claims the key
    with `SET key "" IFEQ <text read> PX 1000` (the atomic step; one winner) and then `DEL`s it. An empty
    tombstone decodes as "no record" and expires by itself if the `DEL` never comes. Removal costs two commands
    instead of one (confirm/claim of the enrollment, CAPTCHA consume); nothing else changes. Minimum server is now
    Valkey 8.1; the ITs take `-Dvalkey.image=…` and were run on `valkey/valkey:9.1` and `valkey/valkey:8.1-alpine`.
    Measured on Valkey 8.1.11 (real adapters, 2000 operations, p50): session create 1 command / 0.32 ms, read by
    token 1 / 0.28 ms, extend 2 / 0.47 ms, delete 1 / 0.22 ms, all as on 9.1; CAPTCHA save 1 / 0.26 ms, consume
    3 commands (`GET`, claim, `DEL`) / 0.72 ms against 2 / 0.46 ms with `DELIFEQ` on 9.1. The hot path (extend)
    is unchanged; only removals pay the extra command. Renamed the same day to
    `CaptchaChallengeStore`: it no longer talks to Valkey itself, only to the transaction store.
20. **Done 2026-11-09.** The transaction record loses its `version` counter (decided the same day: a flow is one
    restricted session of one device, and the store already compares the whole stored text, so the counter only
    repeated what the payload says). `CacheTransaction(kind, id, expiresAt, payload)`; the record is
    `{"schemaVersion":3,"purpose",…,"expiresAtMs",…,"payload":{…}}` at `tx:v3:<purpose>:<id>`. The commands are
    the same (`SET … NX|IFEQ … PXAT`, tombstone claim + `DEL`), so latency does not change. What replaces the
    counter is a rule on the flow: its payload moves forward only (a counter goes up, a state moves on), so an
    earlier text never comes back; `TransactionJsonCodecTest` checks that every step of the enrollment gives a
    text of its own. `createIfAbsent`/`overwrite` no longer refuse a "non-fresh" transaction (there is no such
    thing any more). Records at `tx:v2:` are not read: they lived at most 10 minutes (enrollment) or 5 minutes
    (CAPTCHA), so an enrollment or a challenge in flight at deploy starts again. The session record
    (`session:v3`, `sessionVersion`) is untouched: it is the contract shared with the BFF (DD 22).
    `mvn -o verify`: 341 unit tests, 45 ITs.
21. **Done 2026-11-09.** A repeated `init` or `verify` gets its first answer again (decided the same day; it
    replaces "init from the same session twice is `409`" of turn 3 and "verify runs once"). The case is an app
    that lost the response, or sent the request twice: before, it got `409` and the customer had to log in again.
    - `init` from the session that already started the enrollment: the same `enrollmentId`, Ksrv, sealed challenge
      and deadline, read from the transaction; no new key pair, no new challenge, nothing written. It answers the
      same after `verify` too. A repeat that names another key or platform is another request: `409`. A repeat
      may leave the key and platform out.
    - `verify` once the key is proven (`MFA_REQUIRED`): the same `mfaTransactionId` and deadline; the response
      is not checked again, no attempt is counted, the MFA service is not called. Before the proof nothing
      changes: every answer costs an attempt, and after an MFA outage the app calls verify again (DD 20 §5.2).
    - For this the enrollment payload keeps two more values: `sealedChallenge` (the JWE sent to the device; Auth
      cannot open it and still keeps only the digest of the challenge) and `mfaExpiresAt` (the deadline verify
      answered: the earlier of the MFA's and the enrollment's). The record moves to `tx:v4:` / `schemaVersion`
      4; records at `tx:v3:` are not read (they lived at most 10 minutes).
    - `EnrollmentTransactions`: `findOfDevice` (public), `findStartedBy`, `makeRoomFor(earlierTransaction)`; init
      still reads the record once. Valkey calls: first init 2 (`GET`, `SET NX`), repeated init 1 (`GET`), repeated
      verify 1 (`GET`).
    - Not changed: `confirm` (a repeat after the commit is still `409`), and `approve` / `authorize` of the
      approval path (database), which still answer `409` on a repeat.
    `mvn -o verify`: 346 unit tests, 45 ITs (Valkey 9.1).
22. **Done 2026-11-09.** A repeated `approve` by the device that approved gets the same FACE + OTP check again
    (decided the same day; before, `409`, and the request then hung until its 24 h window ended because the
    primary device could not get the `mfaTransactionId` back). The row keeps the MFA transaction but not its
    deadline, so `approve` sends the MFA service the same `create` again (same `authOperationId` and body: the
    create is built from values approve does not change) and the service answers with the check it already
    opened (DD 20 §5.2). No migration, nothing written on a repeat. Guards: a request another device approved is
    still `409` and does not reach the MFA service; when the MFA service answers a repeat with another transaction
    than the row holds, the repeat is `409` and the row keeps the first. Cost of a repeat: one MFA call. This
    leans on the MFA service returning the same transaction for the same `authOperationId`, which the MFA team has
    not confirmed yet (DD 20 §5.7); until it does, the guard keeps a repeat from switching the request to a
    second check. `authorize` is not changed in this turn.
    `mvn -o verify`: 349 unit tests, 45 ITs (Valkey 9.1).
23. **Done 2026-11-09.** A repeated `authorize` by the approving device, once the token is out, gets a new token
    (decided the same day; before, `409`, and the QR could never be shown when the first answer was lost). The
    first token cannot be handed out again because Auth keeps only its digest (slice 6), so the repeat makes a
    new one and overwrites the digest: the earlier token stops working. What does not move: `authorizationExpiresAt`
    (a repeat cannot buy the QR more than its 180 s) and the claim attempts already counted. The MFA service is
    not asked again; `MFA_CONFIRMED_AT` keeps the time of the first authorize. `409` when the token's deadline has
    passed (nothing is written; the new device's claim closes the request as before), when another device
    approved, or when a racing claim changed the row first (version compare). `DeviceEnrollment` gained
    `reissueAuthorization`, `wasApprovedBy` and `isAuthorized`; `ApprovalRequests.findOpen` reads the open
    request at whichever step. With turns 21 and 22, a lost response at `init`, `verify`, `approve` or
    `authorize` no longer strands the customer.
    `mvn -o verify`: 352 unit tests, 45 ITs (Valkey 9.1).

Slice 11 is complete. Still open (see "Not in this slice"): the BFF minting the assertion, mTLS / key rotation,
and a database guard for one open approval request per device.

## Not in this slice

- The BFF does not mint these assertions yet (`mobile-bff` has no Auth admission code). Until it does, the
  trusted-device routes are reachable only by a caller holding the BFF key (tests).
- mTLS / workload identity between BFF and Auth, and BFF key rotation (one pinned key now).
