# Slice 2 — password login, session, logout, extend (DB phase 1b)

Status: **implemented 2026-10-25** (turns 1–4; see README for the test run). Deviations from the plan: the `SessionStore` port is addressed by `SessionLookup`/`StoredSession`; logout takes a `LogoutCommand`; the filter resolves its own locale. Follows [ARCHITECTURE.md](../../ARCHITECTURE.md);
contracts: DD `06-dpop-native-token-profile` (token + envelope), `16-redis-authority-contract`
(key/HASH/TTL), flow 16 + doc 18 (extend), `03-api-catalog` (error codes), RK01–RK12.

## Decisions taken (2026-10-25)

| Topic | Decision |
|---|---|
| URL prefixes | `/api/ns/**` no session, `/api/**` session-checked, `/internal/**` service-to-service |
| Session fields | customerId, sessionId, deviceId (optional), status, channel |
| Trusted device | not in this slice (slice 3, `TrustedDeviceService` called by `LoginService`) |
| Caller authentication | none yet (`/internal`, `/api/ns` open on the internal network) |
| Token delivery | **JWE envelope now**: `ECDH-ES` / `A256GCM` to the app's P-256 `Kenc` sent in the login body (DD 06). No Auth receipt signature yet (needs a trust-anchor distribution contract) |
| Keycloak | Direct Grant (`grant_type=password`) with `client_id` + `client_secret`; verify the KC ID token signature against the realm JWKS and match `iss`/`sub` to the identity row |
| Lockout | not in this slice (phase 2); same `INVALID_CREDENTIALS` for unknown user and wrong password |
| Session filter | minimal: `/api/**` except `/api/ns/**` needs `Authorization: Bearer <opaque token>`; invalid → `401 SESSION_REQUIRED` |

Deviations from the DD target, deliberately deferred: no DPoP/Kreq binding, no Idempotency-Key,
no Auth receipt, no Redis guards/generation, no `private_key_jwt`. Each is a later slice.

## API

| Path | Caller | Request | Responses |
|---|---|---|---|
| `POST /api/ns/v1/login` | app via BFF | `{userName, password, channel, deviceId?, tokenEncryptionKey: <P-256 public JWK>}` | `201 {tokenEnvelope, status:"ACTIVE", idleExpiresAt, absoluteExpiresAt}`; `401 INVALID_CREDENTIALS`; `403 ACCOUNT_NOT_READY`; `400 REQUEST_REJECTED`; `503 LOGIN_UNAVAILABLE` |
| `POST /api/v1/logout` | app via BFF, `Authorization: Bearer k1.<43>` | none | `204`; `401 SESSION_REQUIRED` |
| `POST /internal/v1/sessions/extend` | BFF after admission | `{sessionLookup:{lookupKeyVersion, lookupDigest}, admissionId, admittedAt, routeId}` | `200 {idleExpiresAt, absoluteExpiresAt}`; `400 REQUEST_REJECTED`; `410 SESSION_GONE`; `409 SESSION_CONFLICT`; `503 TEMPORARILY_UNAVAILABLE` |

`tokenEnvelope` = compact JWE, header `{alg:"ECDH-ES", enc:"A256GCM", typ:"BANKING_TOKEN", ver:1, kid:<Kenc thumbprint>}`,
payload `{token:"k1.<43>", status, customerId, idleExpiresAt, absoluteExpiresAt}`. The plaintext token
never appears in a response or a log.

## Domain (`domain.model`)

- `Session` (record, `@Builder(toBuilder)`): `SessionId`, `CustomerId`, `Optional`-free `deviceId` (nullable `DeviceId`),
  `Channel`, `SessionStatus` (ACTIVE, ENDED), `createdAt`, `idleExpiresAt`, `absoluteExpiresAt`, `sessionVersion`.
  Rules: `start(now, policy)`; `isLive(now)`; `extend(admittedAt, policy)` = `min(absolute, max(idle, admittedAt+idle))`,
  throws `SessionStateException` when not ACTIVE or expired; `end()`.
- `SessionPolicy` (record): idle 15 min, absolute 20 min, max admittedAt skew — passed in from config (§12).
- `OpaqueToken` (`k1.` + 43 base64url chars; redacted `toString`), `SessionId` (UUID), `DeviceId`, `Channel` (enum: MOBILE, WEB … from contract), `Password` (char data, redacted, never in records that are logged).
- `domain.exception.SessionStateException`.

## Application

`port.in`: `LoginUseCase` (`LoginCommand{userName, password, channel, deviceId?, tokenEncryptionKey}` →
`LoginResult`: `Authenticated(envelope, status, deadlines)` | `InvalidCredentials` | `AccountNotReady` | `Unavailable`),
`LogoutUseCase` (`LogoutCommand{token}` → `LogoutResult`: `Ended` | `NoSession`),
`ExtendSessionUseCase` (`ExtendSessionCommand{lookupKeyVersion, lookupDigest, admittedAt, routeId}` →
`ExtendSessionResult`: `Extended(deadlines)` | `Rejected` | `Gone` | `Conflict` | `Unavailable`),
`CurrentSessionUseCase` (`resolve(token)` → `Optional<SessionSummary>`; used by the filter).

`port.out`: `CredentialVerifierPort.verify(userName, password)` → `Verified(issuer, subject)` | `Rejected` (throws
`PartnerUnavailableException`); `CustomerAuthenticationRepository.findByUserName` → identity row (customerId, issuer,
subject, status); `SessionStore` — `create(Session, OpaqueToken)`, `findByToken(OpaqueToken)`, `findByLookup(version, digest)`,
`extendIfCurrent(Session changed)` (CAS on sessionVersion → `Optional<Session>`), `deleteIfCurrent(Session)`;
`TokenEnvelopeSealer.seal(recipientJwk, payload)` → compact JWE (crypto lives in an adapter, not in the service);
`OpaqueTokenGenerator`.

`service`: `LoginService` (implements `LoginUseCase`): find identity → verify password → match issuer/subject →
`Session.start` → `sessions.create` → `sealer.seal`. `SessionService` (implements `LogoutUseCase`,
`ExtendSessionUseCase`, `CurrentSessionUseCase`): the CAS loop (≤3 re-reads with the same `admittedAt`, then `Conflict`).

## Adapters

- `adapter.out.keycloak.KeycloakDirectGrantAdapter` (+ `dto.DirectGrantResponse`, reuse `TokenResponse`): POST token
  endpoint, `grant_type=password`, `scope=openid`; 401/400 `invalid_grant` → `Rejected`; verify `id_token` with Nimbus
  against cached realm JWKS (`JwksVerifier` in the adapter); other statuses/timeouts → unavailable.
- `adapter.out.valkey` (new tech package): `SessionKeys` (RK02/RK03 factory: `forToken(token)`, `forLookup(version, digest)`;
  HMAC key material injected), `SessionHashCodec` (exact field set, schemaVersion=1, strict parse → absent session),
  `ValkeySessionAdapter` implements `SessionStore` with `StringRedisTemplate`: `HSET`+`PEXPIREAT` on create;
  `SessionCallback` WATCH → check `sessionVersion` → MULTI (`HSET idleExpiresAtMs`, `HINCRBY sessionVersion`, `PEXPIREAT`) → EXEC
  for extend; WATCH/MULTI `DEL` for logout. No Lua, no guards (integration-only per contract 16).
- `adapter.out.jose.NimbusTokenEnvelopeSealer` implements `TokenEnvelopeSealer` (nimbus-jose-jwt 10.x is cached offline);
  rejects non-P-256, private-key members, unsupported `kty`.
- `adapter.in.web`: `LoginController`, `SessionController` (logout), `SessionExtensionController`; DTOs
  `LoginRequest` (`tokenEncryptionKey` as a JWK map), `LoginResponse`, `ExtendSessionRequest/Response`; mappers
  `LoginWebMapper`, `SessionWebMapper`; `SessionFilter` (`adapter.in.web.common`) for `/api/**` minus `/api/ns/**`,
  calls `CurrentSessionUseCase`, writes `401 SESSION_REQUIRED` envelope itself (filters run before advice), stores the
  session in a request attribute the controller reads.
- Error codes + vi/en texts: `INVALID_CREDENTIALS`, `ACCOUNT_NOT_READY`, `LOGIN_UNAVAILABLE`, `SESSION_REQUIRED`,
  `SESSION_GONE`, `SESSION_CONFLICT`.

## Config

`LoginConfiguration` (`auth.login.enabled=false` default; `LoginProperties`: Keycloak token endpoint/client/secret, realm JWKS
URL, timeouts, `session.idle=PT15M`, `session.absolute=PT20M`, `session.max-admitted-at-skew`, `session.lookup-key-version=k1`,
`session.lookup-hmac-key-base64` ≥32 bytes) → `SessionPolicy` plain record for the services (§12 "cohesive settings").
`ValkeyConfiguration`: `spring.data.redis.*` connection, `StringRedisTemplate`, the `SessionStore` bean typed by its port.
`SessionFilter` registered only when `auth.login.enabled=true`.

## Tests

domain `SessionTest`, `OpaqueTokenTest`; `LoginServiceTest`, `SessionServiceTest` (in-memory `SessionStore` double with
version CAS); `SessionHashCodecTest` (vectors, unknown field → absent); `SessionKeysTest` (stable HMAC vector, RK12);
`KeycloakDirectGrantAdapterTest` (MockRestServiceServer with a test-signed ID token); `NimbusTokenEnvelopeSealerTest`
(round-trip with a generated P-256 key, wrong key fails); `ValkeySessionAdapterIT` (Testcontainers `valkey/valkey:9.1`:
create/TTL, concurrent extend → one wins, logout, expired); `@WebMvcTest` for the three controllers and the filter;
`LoginConfigurationTest`; `ApplicationBootIT` extended: login → logout against MySQL + Valkey with Keycloak port mocked.
ArchUnit: add `adapter.out.valkey` and `adapter.out.jose` as onion adapters; `*Filter` in `adapter.in.web.common`.

## Turns (one per review)

1. Domain + application (ports, services, in-memory doubles) + `ErrorCodes`/catalogues + ArchUnit update; `mvn -o test`.
2. Valkey adapter (`SessionKeys`, codec, adapter) + IT on `valkey/valkey:9.1`; `ValkeyConfiguration`.
3. Keycloak Direct Grant adapter + Nimbus sealer + tests.
4. Web: controllers, DTOs, mappers, `SessionFilter`, `LoginConfiguration`, boot IT, README/ARCHITECTURE "current" note;
   `mvn -o clean verify`.
