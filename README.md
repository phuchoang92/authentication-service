# Authentication Service v1 — database simplification in progress

**Current warning:** V11 retires the old journey/operation/device-key storage cluster;
V12 removes `auth_customer_app` on an empty isolated device schema. Current device rows
use `channel` instead of `app_id` and `is_primary` instead of a separate primary pointer.
V13 adds an Auth-owned, encrypted TOTP credential for each trusted device. The verifier
accepts six-digit SHA-1 codes at 30-second intervals with a ±1-step window, consumes
each matched step once in MySQL, and refuses a revoked/expired binding. It is **not**
an enabled login, trust, or transfer factor: no enrollment/provisioning API, challenge
admission, attempt budget, or transfer-policy integration has been implemented. The
the three-code acceptance window still requires server-side rate/attempt limits and a
bound challenge before exposing the verifier through an API.
The old password/device/session persistence path has been removed.
The password endpoint now returns a safe
`TEMPORARILY_UNAVAILABLE` response; it does not call Keycloak or issue a banking token.
It does not write a failure row or lock an operation. This is **not** a working login flow.
Do not deploy this build or use it for login until a replacement password flow and its
tests are completed. V11 rejects populated old tables and is not a data migration.
V11/V12 migration and DB-only revoke tests pass on isolated MySQL 8.4. This does not
prove a replacement password login; that flow remains unavailable.

This is the isolated, clean-build G1 source tree, renamed from `authentication-service-rebuild` after the old project was removed. It is not connected to the running database, Redis, deployment, or Maven reactor. The design input is `../docs/DD/target` and the coding authority is `../docs/authentication-documentation/docs/design-v1/code-design-rules-and-patterns.md`.

## What G1 provides

- Standalone Spring Boot 4.1.1 / Java 25 / Maven wrapper 3.9.11, one Maven module under `com.vpbank.dcp`.
- JDK-only `core` ports and values; Spring/HTTP/JPA/Redis/JOSE implementations in `infrastructure`.
- Strict JSON parsing, safe public errors, redacted secret-bearing values, configured public URI, stateless Spring Security X.509 with exact workload URI-SAN authorization, outbound TLS 1.3 client identity/trust factory.
- Pinned biometric Keycloak context verifier, Spring Security DPoP decoder, typed enrollment JWS verifier, JWE envelope inspector, JCS command digest and signing-input codec. Password now travels through authenticated TLS to standard Keycloak Direct Grant; OTP remains an MFA-recipient JWE. Auth never decrypts OTP JWE.
- Fresh MySQL 8.4 Flyway schema (6 current `auth_` tables after V13). V10 adds the trusted-device foundation; V11 retires empty old login/device storage; V12 removes empty `auth_customer_app` and moves primary to `auth_trusted_device`; V13 adds the encrypted TOTP credential. V1–V12 and their checksums are unchanged.
- Dedicated Redis key factories and a development/integration-only online session store. Replay uses native `SET NX` with expiry; session and nonce records use Redis hashes with TTL. There is no Lua or Redis Authority Control implementation. Redis run-ID changes close old sessions, but multi-key activation, touch and revocation are **not atomic**.

## G2 implementation status

The details below describe the **retired pre-V11 slice** for code navigation only.
It is not wired for requests on the current schema. Its old tests characterize that
slice and cannot establish current login acceptance.

G2 has started, but it is **not an accepted login service**. Implemented and unit-tested so far:

- Customer snapshot validation and monotonic block-watermark decisions; HTTPS Customer resolve/status adapter for the assumed contract.
- Typed trusted-device route rules that reject a supplied invalid candidate instead of silently treating it as a new device.
- Standard Keycloak Direct Grant adapter with a configurable confidential client ID and `CLIENT_SECRET_POST` or `PRIVATE_KEY_JWT` authentication, no automatic timeout retry, generic wrong-password rejection, and pinned ID-token signature/issuer/audience/azp/time verification. Its returned OAuth tokens are not exposed to App.
- Customer and Keycloak adapters now share a service-local bounded HTTP exchange component for endpoint allowlisting, total exchange deadline/cancellation, response size, encoding and UTF-8 checks. Partner DTOs, status interpretation and failure mapping remain in their respective adapters. This is not yet a separately published library or proof of live Customer/Keycloak interoperability.
- Opaque 256-bit token issuance, redacted token values, existing exact-token HMAC lookup, and pure 15-minute idle/one-hour absolute deadline rules. A separate issuer encrypts a supplied banking token to software P-256 Kenc with ECDH-ES/A256GCM and signs a receipt covering exact envelope bytes and key bindings.

The G2 contract and reservation gate have advanced:

- V3 Flyway migration pins the server HMAC key ID for password operations and permits a binding-free `ISSUE_PENDING` intent. The one-shot Kreq/Kdev proof and command-HMAC vectors are checked by Java tests.
- Kreq/Kdev/Kenc binding verification, an atomic Redis replay gate, and an HMAC-protected semantic command reservation are implemented. MySQL tests cover duplicate reservation, concurrent insert, rollback, Kdev lookup and single dispatch claim. A component test uses real MySQL and Redis across two service instances; JOSE verification is tested separately, not stubbed in production code.
- Isolated stock Keycloak 26.7.1 integration tests cover both `private_key_jwt` and `client_secret_post`, Direct Grant and a pinned verifier for the issued ID token. These tests call the token endpoint directly over a test-only HTTP container network; they do not prove production mTLS routing or a complete Auth use case.
- An internal password-credential check now invokes admission first, atomically claims the journey and operation as `CREDENTIAL_PROCESSING`/`DISPATCHED` in MySQL, then sends the original credential to Keycloak once. A definite invalid grant is durably `REJECTED`; an unavailable/unknown reply is durably `UNCERTAIN` and is never redispatched under the same operation. A caller interrupted *after reservation but before dispatch* can retry the identical command with fresh proof; MySQL grants that dispatch to only one caller. Once dispatched, retry reads the committed operation state, including a definite rejection, without another Keycloak call. MySQL concurrency tests caught and corrected a deadlock by locking the journey before the operation. This component does not create a banking session or expose an HTTP success response.
- After a verified Keycloak identity, an internal Customer snapshot check resolves immutable `issuer/sub`, rejects blocked/missing customers, and refuses stale, future-dated or unavailable snapshots. Its maximum age must be supplied explicitly; it does not choose the still-open production freshness policy. A short subject-first MySQL transaction now creates or checks immutable Customer/Keycloak identity ownership, subject-App access and subject deny guards, then attaches the owner to the original journey and confirms the original operation. A conflicting owner or a newer unprocessed Customer block watermark cannot be accepted by a login snapshot. This still does not authorize token issuance: device routing, current online guards and activation are separate gates.
- Verified `issuer/sub` is now persisted before Customer resolution. If Customer is temporarily unavailable, the same command can resume from that durable identity without resending the password. The original confirmed owner can also be read after a lost reply.
- The device route uses the current owner, installation, active binding and exact pinned Kdev thumbprint. An invalid claimed binding is rejected, not downgraded to `NEW_DEVICE`. Until G3 provides real MFA challenges, `OTHER_TRUSTED`/`NEW_DEVICE` can be durably frozen as `MFA_UNAVAILABLE`; retry cannot redispatch the password or issue a token. The matching design/OpenAPI response is 503 `TEMPORARILY_UNAVAILABLE`, with no challenge or pending session.

Password ingress uses a direct typed JSON body with username/password unchanged; `DPoP` and `Idempotency-Key` are separate HTTP headers. BFF forwards body bytes directly without a Base64 or `original` envelope. Auth bounds the body to 64 KiB, rejects duplicate/unknown JSON fields, validates headers separately and derives the public DPoP target from trusted configuration.

The password HTTP boundary keeps request and response DTOs in
`infrastructure.adapter.in.web.password.dto`. `PasswordLoginRequest` retains the direct
validated JSON body and input-only password; `PasswordLoginResponse` is the typed union
of ACTIVE, PROCESSING and error DTOs. The controller and response mapper return
`ResponseEntity<PasswordLoginResponse>` rather than untyped response maps. The existing
JSON names, response statuses, UUID strings, date-time strings and response headers stay
unchanged. `DpopProofFilter` and its verified-proof attribute constants live in
`infrastructure.adapter.in.web.security` (with constants under `security.constant`).

Spring Security owns the stateless inbound security chain. X.509 authenticates the TLS workload certificate against the exact configured URI-SAN allowlist. The password DPoP filter runs after workload authorization and before MVC reads the JSON body; `DPoPProofJwtDecoderFactory` verifies signature/type, and Spring claim validators enforce the server-pinned method/URI, required JTI and 30-second age/5-second future bounds. Auth additionally enforces its configured asymmetric algorithm/key, nonce and token-hash profile. The filter passes a core-owned `VerifiedDpopProof` request attribute containing the verified public JWK, thumbprint and proof-ID digest. The controller/body mapper never forwards raw DPoP into the use case, and Kreq verification no longer reparses or re-verifies it. Shared replay remains in the existing Redis password-proof reservation before provider dispatch; Spring's default in-memory DPoP replay cache is not used. Form login, HTTP Basic, browser sessions and request caching are disabled on this private workload boundary. Core has no Spring dependencies.

The one-request password route exists at BFF `POST /api/v1/authentications/password` and private Auth `POST /internal/v1/authentications/password`. The BFF route is enabled only with the `integration` profile and explicit mTLS settings. Auth reserves and verifies the one-shot command, checks the current Customer/device route, and can issue an encrypted ACTIVE banking token only for `LAST_TRUSTED` while `AUTH_INTEGRATION_ACTIVE_ENABLED=true` under the `integration` profile. `OTHER_TRUSTED` and `NEW_DEVICE` return safe 503 without a fabricated MFA challenge or token. MFA is an external HTTP service, but the G3 integration is not implemented here. Auth publishes session and nonce records to Redis; its former private banking-request admission endpoint and its dedicated proof/context adapters have been removed. BFF-side Redis admission is a separate implementation task and is not verified by Auth tests.

This is **not** an accepted end-to-end login service. Guarded result retrieval after a lost reply, lock/logout/rotation, Customer event/guard application, full App→BFF→Auth→Keycloak→ACTIVE integration, and the two-second Customer revocation guarantee remain incomplete. A crash after Keycloak acceptance but before the verified identity is persisted still leaves an uncertain operation; the original cannot redispatch the password. Production activation remains fail-closed, and this artifact must not replace the running service. Password no longer requires a custom Keycloak SPI; biometric still does.

The V12 trusted-device schema is staged only on fresh isolated databases. The new
`JpaDeviceRevocationAdapter` records the device status transition, primary-flag clear and
security audit atomically in MySQL; its port result is explicitly **not** public revoke success.
No online Redis denial/guard, Keycloak cleanup, MFA trust completion, biometric flow or runtime
password routing has been switched to these tables. The public password endpoint remains closed.

## Password DPoP configuration

`auth.dpop.enabled` defaults to `true`; `auth.dpop.allowed-algorithms` defaults to `[ES256]`.
The server allowlist supports ES256/ES384/ES512, RS256/RS384/RS512 and PS256/PS384/PS512.
EC curves must match the signature algorithm; RSA public keys require at least 2048 bits.
The password Kreq body proof uses the same allowlist and public key. Kdev/receipt signatures
and Kenc encryption keep their existing algorithms. Unsupported, empty or symmetric
allowlists prevent startup. See the [approved native profile](../docs/DD/target/06-dpop-native-token-profile.md#algorithm-agility).

```yaml
auth:
  dpop:
    enabled: true
    allowed-algorithms: [ES256, PS256]
```

Environment equivalents are `AUTH_DPOP_ENABLED` and `AUTH_DPOP_ALLOWED_ALGORITHMS`
(comma-separated, for example `ES256,PS256`). To skip DPoP verification for local testing,
set `SPRING_PROFILES_ACTIVE=dev` and `AUTH_DPOP_ENABLED=false`. Explicit active profiles
must all belong to `local`, `dev`, `test`, `qa`, `uat`, `staging`, `integration` or `non-prod`.
No active profile, `prod`/`production`, an unknown profile or a mixture containing one of
these prevents startup when verification is disabled. Enabled verification works with
any profile and is the default.

Disabled verification skips DPoP signature, HTTP method/URI, freshness, nonce and token-hash
checks. A parseable DPoP header containing an allowed public JWK, JTI and issued-at is still
required to supply Kreq and replay metadata. The internal result carries
`DISABLED_FOR_NON_PRODUCTION`, rather than claiming verified evidence. Strict JOSE syntax,
header/body limits, key constraints, mTLS workload authentication, Kreq/Kdev body signatures,
command/key binding and shared replay reservations remain enforced. This setting currently
applies to the implemented password ingress, not a BFF banking-session admission route.

## Keycloak client configuration

`auth.keycloak.private-client` selects exactly one client authentication mode at startup.
The user-approved configuration overrides the older target's fixed client ID and exclusive
`private_key_jwt` requirement. Defaults preserve `authentication-service` and `PRIVATE_KEY_JWT`.

| Environment variable | Meaning |
| --- | --- |
| `AUTH_KC_CLIENT_ID` | Confidential client ID; defaults to `authentication-service` |
| `AUTH_KC_CLIENT_AUTHENTICATION_METHOD` | `CLIENT_SECRET_POST` or `PRIVATE_KEY_JWT`; defaults to `PRIVATE_KEY_JWT` |
| `AUTH_KC_CLIENT_SECRET` | Required only for `CLIENT_SECRET_POST`; inject from managed secret configuration |
| `AUTH_KC_CLIENT_PRIVATE_JWK` | Private ES256/P-256 JWK with `kid`, required only for `PRIVATE_KEY_JWT` |
| `AUTH_KC_TOKEN_AUDIENCE` | Exact HTTPS Keycloak token endpoint for this realm |
| `AUTH_KC_REQUEST_TIMEOUT_MS` | Explicit exchange timeout, 1–8000 ms |

For a shared secret, configure `AUTH_KC_CLIENT_AUTHENTICATION_METHOD=CLIENT_SECRET_POST`,
the desired `AUTH_KC_CLIENT_ID`, and `AUTH_KC_CLIENT_SECRET`. In Keycloak enable client
authentication and Direct Access Grants, select **Client Id and Secret**, and supply that
client's secret. The service sends `client_id` and `client_secret` as URL-encoded form
fields. No private client JWK is needed in this mode.

For a signed assertion, select `PRIVATE_KEY_JWT`, supply `AUTH_KC_CLIENT_PRIVATE_JWK`, and
configure the corresponding public key and **Signed JWT** client authenticator in Keycloak.
The form contains `client_id`, `client_assertion_type` and a fresh `client_assertion`, with
the configured client ID as assertion `iss` and `sub`; it contains no `client_secret`.

Unknown modes, blank client IDs and missing selected credentials prevent startup. Unused
credentials are neither required nor parsed, and rejection does not switch authentication
methods or retry. Client credentials remain redacted. Both modes retain the existing mTLS
workload transport and require `AUTH_KC_ID_TOKEN_ISSUER`, `AUTH_KC_ID_TOKEN_KID` and
`AUTH_KC_ID_TOKEN_PUBLIC_JWK` for pinned identity verification. The ID-token `aud` and `azp`
must match the configured client ID exactly.

Verification for this configuration change passed `clean verify`: 190 unit/architecture
tests and 45 isolated integration tests, with no failures, errors or skips. Coverage
includes both authentication modes on stock Keycloak 26.7.1, rejection of a wrong client
secret, configured assertion/ID-token bindings, form encoding and startup validation.
Concurrent DPoP algorithm changes made during the run are outside this verification snapshot.

## Shared session activation

The following describes the removed pre-V11 password path, not the active API. In that path,
password owned credential verification and trusted-device eligibility. After `LAST_TRUSTED`,
the retired login service called the inbound `ActivateSessionUseCase` with
`ActivateSessionCommand(operationId, subjectId)`. `ActivateSessionService` lives in
`core.application.session`; its command and `SessionActivationResult` live beside the
inbound port. The shared core has no password dependency. A command identifies an operation;
current confirmed storage facts still determine whether it may activate.

`SessionRepository`, `SessionCryptography`, `SessionAuthority`, `SessionActivationSnapshot`
and `PreparedSession` describe shared issuance and recovery. `SessionCryptoAdapter`
prepares token delivery, and `RedisSessionAuthority` publishes and checks it using the
existing integration-only Redis mechanics. Typed `SessionAssurance` comes from the
authentication source; Redis and the HTTP response mapper serialize those same values.
The password mapper supplies `MFA_KEY_POSSESSION` / `NONE` / `NOT_APPLICABLE`.

`SessionActivationSnapshot` is an immutable source snapshot with six components:
`SessionActivationContext`, `SessionKeyBindings`, `SessionSecurityVersions`,
`CustomerStatusFreshness`, `SessionAssurance` and biometric availability. The first four
group fourteen formerly flat components; assurance and biometric availability remain explicit.
All nested values retain
value equality, so SQL preparation compares the complete snapshot after acquiring locks.
`currentSnapshot` reads this contract and `PreparedSession.snapshot()` retains it for
publication/recovery. Database projections remain flat database values; the persistence
mapper assembles the grouped core snapshot. Snapshot/key output is redacted.

`PreparedSession` has four immutable components: the confirmed snapshot, `SessionCandidate`,
`SessionDelivery` and `SessionDeadlines`. The candidate groups the intent/session IDs,
generation, versioned `SessionTokenLookup` and exact candidate digest. Delivery groups
the encrypted envelope, signed receipt, DPoP nonce and fixed recovery deadline; idle and
absolute session expiry stay in `SessionDeadlines`. All nested values preserve value
equality and redact output. Persistence mapping still uses the existing flat projections
and explicit three-field escrow codec; the grouped core values are not a new wire format.

The SQL bridge described above was removed with V11. Its core issuance types and crypto
components are not wired into a working password login and must not be treated as proof
of current recovery or activation behavior.

`SessionConfiguration` still assembles integration-only crypto/Redis components.
`PasswordFlowConfiguration` wires a fail-closed unavailable result. Biometric/PIN and
session lifecycle flows are not implemented by this device-schema change.

## Persistence structure

```text
core.port.out.<capability>.<Capability>Repository
    ↑ implements
infrastructure.persistence
    ├── adapter       Jpa<Capability>Adapter (transactions and coordination)
    ├── repository    <Capability>PersistenceRepository / <Capability>JpaRepository / <Capability>Sql
    ├── entity        Current JPA mappings only; no password-operation entity
    ├── projection    immutable database …View values
    ├── mapper        <Capability>PersistenceMapper (DB values → core)
    └── codec         SessionDeliveryEscrowCodec / EscrowedSessionDelivery
```

The active DB-only device capability uses `TrustedDeviceRevocationPersistenceRepository`,
`SecurityAuditPersistenceRepository` and `JpaDeviceRevocationAdapter`. Old CustomerOwner,
PasswordDeviceKey, PasswordDeviceRoute, PasswordSession and intent/escrow SQL repositories
were removed because their tables no longer exist. Persistence groups classes by technical
role; core still groups domain and ports by capability.

Adapters own short transactions, lock ordering, multi-table updates and recovery after
rollback. Internal repositories bind and execute SQL, extract typed database views and
check affected rows; they do not construct domain objects or workflow results. Native SQL
holders remain package-private beside their owning repositories. Existing core-typed
write parameters are retained.

Focused, handwritten, stateless mappers restore domain values and core-owned port
results for retained capabilities. Mappers perform no I/O,
transaction orchestration, clock access or freshness calculation. Views contain database
values instead of domain objects, with defensive byte copies, content equality and
redacted output. The retired `auth_operation` table has no entity, Spring Data repository,
or active failure-recording adapter. Older password/session text below describes the
pre-V11 path and is not evidence of current runtime behavior.

Customer freshness uses the configured maximum age through `CustomerFreshnessPolicy`.
`SessionDeliveryEscrowCodec` remains a tested codec, not active result recovery. V11
removed `auth_authority_intent` and related source tables. V12 has no customer-App row:
the per-customer/channel primary flag is stored on the trusted binding. No code may use
the removed SQL as current login authority.

Architecture tests enforce the new persistence role boundaries, including negative
fixtures: application/controllers use ports, adapters do not execute SQL, repositories do
not construct core values or call adapters/mappers, entity/view types do not contain core
objects, entities stay inside persistence, and mappers do not access I/O or the clock.
Real MySQL tests cover reservation/duplicate recovery, concurrent dispatch, owner conflict
and watermark ordering, read projections after native updates, session preparation,
completion and rollback after a partial multi-table transition. Freshness boundary and
escrow byte/digest regression tests run with the unit suite. These test descriptions are
coverage scope; only an actually completed build establishes verification.

Session intent and escrow deadlines now bind `Timestamp.from(Instant)` through the
configured Hibernate JDBC UTC calendar, matching password operation and Customer writes.
This fixes the previous `LocalDateTime` binding that stored deadlines seven hours early
under a UTC+7 JVM. Explicit `Instant` result mappings also preserve restored deadlines
and the source Customer freshness timestamp in either JVM zone. The facts query adds
only a projection alias; SQL guards/codes, deadline policy and signing bytes stay unchanged.
Maven runs the persistence integration tests under both UTC and `Asia/Ho_Chi_Minh`,
including exact stored deadline values and activation/recovery at those boundaries.

## Build and test

Persistence refactor verification on 2026-10-12: the initial worktree baseline passed
154 tests. The final `clean verify` passed 144 unit/architecture tests and 45 integration
tests, with zero failures, errors or skips, using UTC test JVMs and isolated Testcontainers
storage. These totals describe the complete worktree, which also contained independent
HTTP/Redis work in progress; they are not a count of tests added solely by this refactor.

The subsequent Authority Control removal passed `clean verify` with 144 unit/architecture
and 44 integration tests (188 total, zero failures/errors/skips). MySQL coverage includes
fresh V9 schema creation and upgrading populated V8 storage while preserving Customer
data and V1–V8 checksums. Only isolated test storage was migrated.

The subsequent Spring Security ingress refactor passed `verify` with 176 unit/architecture
and 44 integration tests (220 total, zero failures/errors/skips). Security tests exercise
an actual Spring Security filter chain with generated DPoP signatures and isolated
certificate fixtures, including wrong workload identity, invalid signature/URI, proof
age/skew boundaries, duplicate headers and stateless request isolation. The totals cover
the complete current worktree, including independent persistence changes; they do not
establish a deployed BFF→Auth trust chain or production admission acceptance.

The subsequent persistence role/mapper refactor baseline passed 188 tests. Its
`clean verify` passed 176 unit/architecture and 44 integration tests (220 total, zero
failures/errors/skips), including 23 new mapper/projection regression cases. The full
worktree also contained concurrent Spring Security/crypto changes; the increase from
baseline is not solely attributable to persistence. Tests used UTC JVMs and isolated
Testcontainers storage. SQL query bodies, migrations, Redis and the five core Repository
ports were preserved. Historical verification results above remain unchanged.

The subsequent HTTP DTO and filter-package refactor passed `test` with 180
unit/architecture tests, zero failures/errors/skips. New serialization regressions check
ACTIVE metadata, PROCESSING, errors, expiry bounds and date-time strings; the existing
request-validation and Spring Security filter-chain tests also pass. Storage/provider
integration tests were not rerun for this HTTP-only change.

The subsequent configurable password DPoP change passed `verify` on 2026-10-13 with
233 unit/architecture tests and 45 isolated integration tests, zero failures/errors/skips.
Real-signature tests cover all nine supported algorithms and their Kreq/Kdev/Kenc bindings;
configuration tests cover default/explicit allowlists and non-production/production startup
behavior. The actual Spring Security chain proves disabled verification still requires
workload TLS and valid key metadata, while body-proof signatures remain enforced. These
counts cover the current complete worktree and do not establish App/BFF interoperability
with the newly selectable algorithms or deployment acceptance.

The shared session activation extraction passed `clean verify` on 2026-10-13 with
254 unit/architecture tests, 58 UTC integration tests and 45 repeated persistence tests
under `Asia/Ho_Chi_Minh`, zero failures/errors/skips. Verification used an isolated copy
whose complete source/build inputs matched the current tree, avoiding concurrent writes
to the main build output. Coverage includes exact candidate/envelope/receipt/nonce retry,
SQL lock revalidation and multi-table rollback, Redis schema/assurance, response mapping,
and timezone-independent deadlines and Customer freshness. The password-source activation
integration starts from confirmed test storage; it does not establish a deployed App/BFF
or partner flow. Totals include the complete worktree's independent changes. Reports are
saved under `target/session-refactor-verification/`; historical results above stay intact.

The grouped `SessionActivationSnapshot` refactor was checked on 2026-10-13: all 255
unit/architecture tests passed; all 15 session MySQL integration cases passed under both
UTC and `Asia/Ho_Chi_Minh`, and all four Redis session cases passed. The new cases reject
changed keys, security versions, Customer freshness, assurance and biometric availability
before any activation writes. SQL text, candidate digest inputs, escrow serialization and
the nine pre-existing migration checksums were unchanged. Full `clean verify` on the
captured source was not green: each timezone run had one schema table-count failure
(20 expected, 25 actual) and one populated-V8 upgrade error (`value` cannot be null),
both involving the concurrently added V10 migration. That migration was not modified by
this refactor. Reports are saved under `target/session-snapshot-verification/`.

On the current Mac, the verified command is:

```bash
cd /Users/phuc/BigMoves/mobile-banking/authentication-service
JAVA_HOME=/Users/phuc/Library/Java/JavaVirtualMachines/openjdk-25.0.2/Contents/Home \
./mvnw verify
```

Tests use ephemeral, separate Testcontainers MySQL 8.4, Redis 7.4 and Keycloak 26.7.1 instances. They do not use H2 or the running database/Redis/Keycloak. `./mvnw test` runs unit/architecture/vector tests only; `verify` additionally runs the isolated integration tests. Synthetic vectors are read from `../docs/DD/target/reference/crypto-vectors.json`, `software-key-vectors.json` and `password-one-shot-vectors.json`; older password-JWE cases are historical, not current password acceptance tests.

## Required runtime configuration

`application.yaml` requires explicit MySQL, Redis, server mTLS, workload mTLS, public external origin, BFF workload URI allowlist, bank authority scope, pinned biometric Keycloak context signer, pinned KC ID-token signer, Auth receipt signing key, Customer origin/timeout and Keycloak Direct Grant client identity/timeout. There is no JVM-default-trust fallback. Redis preflight requires a single primary with `noeviction` and an explicitly configured positive memory budget. The simplified Redis path is **not approved for production admission**; the required revocation/failover protocol remains deferred.

The dedicated Redis identity must be permitted to read `INFO server/replication/cluster` and `CONFIG GET maxmemory/maxmemory-policy`, and to execute the required native key commands. Missing permissions close startup/admission; no permissive ACL fallback is configured.

Names of mandatory environment inputs are in `src/main/resources/application.yaml`. Do not use test keys, test certificates, or test profile overrides in deployment.

## G1 verification boundary

| Area | Evidence available | Not yet proven by G1 |
|---|---|---|
| Build and architecture | Maven `verify`; ArchUnit positive and negative fixtures | Dependency policy for future controllers/use cases must be enforced as they are added |
| HTTP and TLS | Strict JSON, safe error and URI tests; Spring Security filter-chain and exact URI-SAN tests; local TLS 1.3 client-certificate handshake | Full BFF→Auth deployment trust chain and real partner TLS interoperability |
| Crypto | Shared DPoP, context, enrollment, token-envelope JWE and signing-input vectors | Keycloak/MFA verifier interoperability, App receipt/decryption interop and software-key extraction threat acceptance |
| MySQL | Flyway on fresh MySQL 8.4; constraints, concurrent CAS, rollback and V8→V9 upgrade | Cross-system operation/recovery transactions from G2/G3 |
| Redis | Real Redis replay, generation marker and session/nonce records under the integration profile | Atomic revocation, failover fencing, Customer block admission and production recovery |

Open decisions remain in `../docs/DD/target/17-implementation-readiness.md`: Customer event broker and outage policy under the 2-second block bound, operational nonce/lease timing, retention/privacy, password abuse controls and real Customer/MFA provider agreement. No permissive production defaults were chosen here.
