# Authentication Service v1 — G1 complete, G2 in progress

This is the isolated, clean-build G1 source tree, renamed from `authentication-service-rebuild` after the old project was removed. It is not connected to the running database, Redis, deployment, or Maven reactor. The design input is `../docs/DD/target` and the coding authority is `../docs/authentication-documentation/docs/design-v1/code-design-rules-and-patterns.md`.

## What G1 provides

- Standalone Spring Boot 4.1.1 / Java 25 / Maven wrapper 3.9.11, one Maven module under `com.vpbank.dcp`.
- JDK-only `core` ports and values; Spring/HTTP/JPA/Redis/JOSE implementations in `infrastructure`.
- Strict JSON parsing, safe public errors, redacted secret-bearing values, configured public URI, stateless Spring Security X.509 with exact workload URI-SAN authorization, outbound TLS 1.3 client identity/trust factory.
- Pinned biometric Keycloak context verifier, Spring Security DPoP decoder, typed enrollment JWS verifier, JWE envelope inspector, JCS command digest and signing-input codec. Password now travels through authenticated TLS to standard Keycloak Direct Grant; OTP remains an MFA-recipient JWE. Auth never decrypts OTP JWE.
- Fresh MySQL 8.4 Flyway schema (20 `auth_` tables) and short transaction tests. Additive V8 renames `auth_subject` to `auth_customer`; V9 removes the unused `auth_authority_control` table after retiring its SQL lease capability. V1–V8 and their checksums are unchanged.
- Dedicated Redis key factories and a development/integration-only online session store. Replay uses native `SET NX` with expiry; session and nonce records use Redis hashes with TTL. There is no Lua or Redis Authority Control implementation. Redis run-ID changes close old sessions, but multi-key activation, touch and revocation are **not atomic**.

## G2 implementation status

G2 has started, but it is **not an accepted login service**. Implemented and unit-tested so far:

- Customer snapshot validation and monotonic block-watermark decisions; HTTPS Customer resolve/status adapter for the assumed contract.
- Typed trusted-device route rules that reject a supplied invalid candidate instead of silently treating it as a new device.
- Standard Keycloak Direct Grant adapter with confidential `authentication-service`/`private_key_jwt`, no automatic timeout retry, generic wrong-password rejection, and pinned ID-token signature/issuer/audience/azp/time verification. Its returned OAuth tokens are not exposed to App.
- Customer and Keycloak adapters now share a service-local bounded HTTP exchange component for endpoint allowlisting, total exchange deadline/cancellation, response size, encoding and UTF-8 checks. Partner DTOs, status interpretation and failure mapping remain in their respective adapters. This is not yet a separately published library or proof of live Customer/Keycloak interoperability.
- Opaque 256-bit token issuance, redacted token values, existing exact-token HMAC lookup, and pure 15-minute idle/one-hour absolute deadline rules. A separate issuer encrypts a supplied banking token to software P-256 Kenc with ECDH-ES/A256GCM and signs a receipt covering exact envelope bytes and key bindings.

The G2 contract and reservation gate have advanced:

- V3 Flyway migration pins the server HMAC key ID for password operations and permits a binding-free `ISSUE_PENDING` intent. The one-shot Kreq/Kdev proof and command-HMAC vectors are checked by Java tests.
- Kreq/Kdev/Kenc binding verification, an atomic Redis replay gate, and an HMAC-protected semantic command reservation are implemented. MySQL tests cover duplicate reservation, concurrent insert, rollback, Kdev lookup and single dispatch claim. A component test uses real MySQL and Redis across two service instances; JOSE verification is tested separately, not stubbed in production code.
- An isolated stock Keycloak 26.7.1 integration test uses the `authentication-service` confidential client with `private_key_jwt`, Direct Grant and a pinned verifier for its issued ID token. This test calls the token endpoint directly over a test-only HTTP container network; it does not prove production mTLS routing or a complete Auth use case.
- An internal password-credential check now invokes admission first, atomically claims the journey and operation as `CREDENTIAL_PROCESSING`/`DISPATCHED` in MySQL, then sends the original credential to Keycloak once. A definite invalid grant is durably `REJECTED`; an unavailable/unknown reply is durably `UNCERTAIN` and is never redispatched under the same operation. A caller interrupted *after reservation but before dispatch* can retry the identical command with fresh proof; MySQL grants that dispatch to only one caller. Once dispatched, retry reads the committed operation state, including a definite rejection, without another Keycloak call. MySQL concurrency tests caught and corrected a deadlock by locking the journey before the operation. This component does not create a banking session or expose an HTTP success response.
- After a verified Keycloak identity, an internal Customer snapshot check resolves immutable `issuer/sub`, rejects blocked/missing customers, and refuses stale, future-dated or unavailable snapshots. Its maximum age must be supplied explicitly; it does not choose the still-open production freshness policy. A short subject-first MySQL transaction now creates or checks immutable Customer/Keycloak identity ownership, subject-App access and subject deny guards, then attaches the owner to the original journey and confirms the original operation. A conflicting owner or a newer unprocessed Customer block watermark cannot be accepted by a login snapshot. This still does not authorize token issuance: device routing, current online guards and activation are separate gates.
- Verified `issuer/sub` is now persisted before Customer resolution. If Customer is temporarily unavailable, the same command can resume from that durable identity without resending the password. The original confirmed owner can also be read after a lost reply.
- The device route uses the current owner, installation, active binding and exact pinned Kdev thumbprint. An invalid claimed binding is rejected, not downgraded to `NEW_DEVICE`. Until G3 provides real MFA challenges, `OTHER_TRUSTED`/`NEW_DEVICE` can be durably frozen as `MFA_UNAVAILABLE`; retry cannot redispatch the password or issue a token. The matching design/OpenAPI response is 503 `TEMPORARILY_UNAVAILABLE`, with no challenge or pending session.

Password ingress uses a direct typed JSON body with username/password unchanged; `DPoP` and `Idempotency-Key` are separate HTTP headers. BFF forwards body bytes directly without a Base64 or `original` envelope. Auth bounds the body to 64 KiB, rejects duplicate/unknown JSON fields, validates headers separately and derives the public DPoP target from trusted configuration.

Spring Security owns the stateless inbound security chain. X.509 authenticates the TLS workload certificate against the exact configured URI-SAN allowlist. The password DPoP filter runs after workload authorization and before MVC reads the JSON body; `DPoPProofJwtDecoderFactory` verifies signature/type, and Spring claim validators enforce the server-pinned method/URI, required JTI and 30-second age/5-second future bounds. Auth additionally enforces its ES256/P-256, nonce and token-hash profile. The filter passes a core-owned `VerifiedDpopProof` request attribute containing the verified public JWK, thumbprint and proof-ID digest. The controller/body mapper never forwards raw DPoP into the use case, and Kreq verification no longer reparses or re-verifies it. Shared replay remains in the existing Redis password-proof reservation before provider dispatch; Spring's default in-memory DPoP replay cache is not used. Form login, HTTP Basic, browser sessions and request caching are disabled on this private workload boundary. Core has no Spring dependencies.

The one-request password route exists at BFF `POST /api/v1/authentications/password` and private Auth `POST /internal/v1/authentications/password`. The BFF route is enabled only with the `integration` profile and explicit mTLS settings. Auth reserves and verifies the one-shot command, checks the current Customer/device route, and can issue an encrypted ACTIVE banking token only for `LAST_TRUSTED` while `AUTH_INTEGRATION_ACTIVE_ENABLED=true` under the `integration` profile. `OTHER_TRUSTED` and `NEW_DEVICE` return safe 503 without a fabricated MFA challenge or token. MFA is an external HTTP service, but the G3 integration is not implemented here. Auth publishes session and nonce records to Redis; its former private banking-request admission endpoint and its dedicated proof/context adapters have been removed. BFF-side Redis admission is a separate implementation task and is not verified by Auth tests.

This is **not** an accepted end-to-end login service. Guarded result retrieval after a lost reply, lock/logout/rotation, Customer event/guard application, full App→BFF→Auth→Keycloak→ACTIVE integration, and the two-second Customer revocation guarantee remain incomplete. A crash after Keycloak acceptance but before the verified identity is persisted still leaves an uncertain operation; the original cannot redispatch the password. Production activation remains fail-closed, and this artifact must not replace the running service. Password no longer requires a custom Keycloak SPI; biometric still does.

## Persistence structure

```text
core.port.out.<capability>.<Capability>Repository
    ↑ implements
infrastructure.persistence
    ├── adapter       Jpa<Capability>Adapter (transactions and coordination)
    ├── repository    <Capability>PersistenceRepository / <Capability>JpaRepository / <Capability>Sql
    ├── entity        PasswordOperationEntity
    ├── projection    immutable database …View values
    ├── mapper        <Capability>PersistenceMapper (DB values → core)
    └── codec         PasswordDeliveryEscrowCodec / EscrowedPasswordDelivery
```

The five SQL capabilities are CustomerOwner, PasswordOperation, PasswordDeviceKey,
PasswordDeviceRoute and PasswordSession. Persistence groups classes by technical role,
without customer/password/session subpackages. Core still groups domain and ports by
capability. Redis ports retain their existing names. There are no compatibility aliases
for the replaced SQL ports.

Adapters own short transactions, lock ordering, multi-table updates and recovery after
rollback. Internal repositories bind and execute SQL, extract typed database views and
check affected rows; they do not construct domain objects or workflow results. Native SQL
holders remain package-private beside their owning repositories. Existing core-typed
write parameters are retained.

Five focused, handwritten, stateless mappers restore domain values and core-owned port
results. Adapters invoke them, for example `queries.verifiedIdentity(id).map(
PasswordOperationPersistenceMapper::toVerifiedIdentity)`. Mappers perform no I/O,
transaction orchestration, clock access or freshness calculation. Views contain database
values instead of domain objects, with defensive byte copies, content equality and
redacted output. The current read paths return views, including Spring Data JPQL
projections backed by `PasswordOperationEntity`; no entity loads or unused entity mapper
methods are introduced solely for mapping.

Spring Data reads operation progress and verified identity through JPQL scalar projections
of an immutable entity mapped to the existing `auth_operation` table, including BINARY(16)
UUIDs. It exposes no save/delete methods. Native SQL handles locked reads, joins and CAS;
no loaded entity is used to decide a mutation. Both JPA query and second-level caches are
disabled.

Customer freshness uses the configured maximum age through `CustomerFreshnessPolicy`;
a snapshot expires exactly at `checkedAt + maxAge`. `PasswordDeliveryEscrowCodec` preserves
the existing JsonMapper encoding and checks SHA-256 using the JDK before decoding stored
bytes. The persistence refactor preserved the API and transaction boundaries; the later
explicit Authority Control removal adds V9 and deletes its unused core port, adapter and
internal SQL repository. It does not remove `auth_authority_intent` or other session data.
The separate three-table target is not implemented by these changes.

Architecture tests enforce the new persistence role boundaries, including negative
fixtures: application/controllers use ports, adapters do not execute SQL, repositories do
not construct core values or call adapters/mappers, entity/view types do not contain core
objects, entities stay inside persistence, and mappers do not access I/O or the clock.
Real MySQL tests cover reservation/duplicate recovery, concurrent dispatch, owner conflict
and watermark ordering, read projections after native updates, session preparation,
completion and rollback after a partial multi-table transition. Freshness boundary and
escrow byte/digest regression tests run with the unit suite. These test descriptions are
coverage scope; only an actually completed build establishes verification.

The new session regressions exposed an existing timezone limitation in the unchanged
`LocalDateTime` native-SQL binding: with the JVM in UTC+7, a UTC deadline can be stored
seven hours earlier. Maven test JVMs explicitly use UTC for reproducible storage checks.
This refactor does not repair that runtime binding or claim support for a non-UTC JVM;
that issue requires a separate change and validation.

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
