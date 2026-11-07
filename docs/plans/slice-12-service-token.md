# Slice 12 — scoped service token for flows without a customer session

Status: **implemented 2026-11-03, turns 1–4** (turn 1: domain + application; turn 2: signer, client-assertion verifier and
filter, replay key factory; turn 3: routes, configuration, boot scenario, docs; turn 4: audit events + V6;
`mvn -o clean verify` after turn 4: 323 unit tests, 39 ITs). Turns 1–3 were committed from outside this session ("refine"); turn 4 is uncommitted.

Some flows have no customer login and no Valkey session, onboarding first of all. The owning service asks Auth for a
short-lived JWT whose `scope` names the flow; the BFF verifies the token and forwards only the routes of that scope.
The token is a bearer credential for one business journey, not a session: nothing is stored for it, it is never
extended, and it carries no customer.

## What the docs decide, and what this slice adds

- The session token (slice 7) is opaque and has no signing key, so there is no signing material to reuse. DD 01 / DD 12
  separate keys by purpose: the service token gets its own ES256 key.
- DD flow 15 describes workload tokens (short-lived, scoped, audience-restricted, "client ID is public; possession of
  the configured private key authenticates the caller", no fabricated customer context) but names no issuer. **This
  slice makes Auth that issuer** — a design addition agreed on 2026-11-03, not a contract already in the DD target.
- DD fixed requirements: every internal hop authenticates the caller workload; network placement is not authentication.
  `/internal` has no caller authentication today (README). This slice adds it for its own route only.
- The 2-second commit-to-deny bound (DD 15 / DD 17) is about customer sessions after a Customer block; this token has
  no customer, so it is stateless.

## Decisions (2026-11-03)

| Topic | Decision |
|---|---|
| Who holds the token | The owning service hands it to the app as the credential of one journey (reading A); the app presents it to the BFF for the rest of that journey. The same endpoint and claims would serve a backend-only token; only the lifetime policy would differ. |
| Route | `POST /internal/v1/service-tokens` (issue) and `GET /internal/v1/service-tokens/jwks` (public signing keys), behind `auth.service-token.enabled`, off by default. |
| Caller authentication | One `Authorization: Bearer <client assertion>`: ES256 JWS, `typ=service-client-assertion+jwt`, `kid` of the caller's pinned public JWK, claims exactly `iss, sub, aud, iat, exp, jti`, `iss` = `sub` = service ID, `aud=authentication-service`, lifetime ≤ 60 s, 5 s skew, `jti` used once (Valkey `service-client-assertion:used:v1:<sha256(jti)>`). Same mechanism as the BFF assertion of slice 11 and as Auth's own `private_key_jwt` toward Keycloak. mTLS stays open, as in slice 11. |
| Request body | `{"scope": "onboarding", "businessReference": "<onboarding request id>"}`; `businessReference` is required by scope `onboarding` (`ServiceScope.businessReferenceRequired()`), 1–128 URL-safe characters. |
| Answers | `200 {token, tokenType:"Bearer", scope, expiresAt}`; `401 REQUEST_REJECTED` (bad, unknown-key, expired or replayed assertion); `403 SCOPE_NOT_ALLOWED` (new code: caller not granted that scope); `400` (body, or scope without its reference); `503 TEMPORARILY_UNAVAILABLE` (replay store). |
| Token | Header `alg=ES256`, `typ=service-token+jwt`, `kid`; no `jwk`/`jku`/`x5c`/`crit`. Claims exactly `iss` (`auth.service-token.issuer`), `sub` (caller service ID), `aud` (`auth.service-token.audience`, the BFF), `scope` (one scope code, space-delimited string so more can follow), `businessReference` (exactly when the scope requires it), `iat`, `exp`, `jti` (random UUID). |
| Key | One private P-256 JWK with `kid`, `auth.service-token.signing-private-jwk`, used for nothing else. Rotation in v1 = publish the new public key in the JWKS for one lifetime, then sign with it (same single-key limit as the BFF key today). |
| Lifetime | `auth.service-token.lifetime`, **no default**, validated to 1–30 minutes (DD 17: no invented policy defaults). An onboarding journey suggests about 15 minutes. |
| Statefulness | Stateless. No Valkey record for the token; the BFF reads nothing to verify it. Revocation = expiry plus removing the caller's key/grant from configuration. No proof of possession for the app-held token in v1. |
| Grants | `auth.service-token.callers.<serviceId>.{public-jwk, scopes}` → `ServiceScopeGrants`; an unlisted caller or an ungranted scope is `403`. |
| Audit | Deferred to turn 4, after slice 9 is committed: `SecurityAuditEvent` and `SECURITY_AUDIT_EVENT` are login-shaped (`CHANNEL NOT NULL`), so recording `SERVICE_TOKEN_ISSUED` / `SERVICE_TOKEN_REFUSED` needs an additive V6 migration and edits to slice-9 files still in flight. |

## BFF-side verification (for the end-to-end contract)

- Parse `Authorization: Bearer <jwt>` as a compact JWS; require `alg=ES256`, `typ=service-token+jwt`, a `kid` found in
  Auth's JWKS (cached; refresh once on an unknown `kid`), no embedded key headers.
- Require the exact claim set; `iss` = Auth issuer, `aud` contains the BFF, `exp` in the future and `iat` not in the
  future (5 s skew).
- `scope` → route allowlist: `onboarding` forwards only the onboarding routes; any other route is `403`, an unknown
  scope `401`. `sub` must be a service allowed to start that scope (e.g. `onboarding-service`).
- Forward the token unchanged; the owning service verifies it with the same JWKS and checks `businessReference`
  against the request's onboarding ID (flow 15: domains verify locally).
- Never a session: no Valkey read, no extend, no session routes.

## Changes

Turn 1 (done):
- `domain.enums.ServiceScope` — `ONBOARDING("onboarding", businessReferenceRequired=true)`, `code()`, fail-closed
  `fromCode`; name frozen in `DomainEnumCodesTest`, code in `ServiceScopeTest`.
- `domain.model.ServiceId` (`[a-z0-9-]{3,64}`), `BusinessReference` (`[A-Za-z0-9._:-]{1,128}`),
  `ServiceTokenClaims` (builder; expiry after issue; reference present exactly when the scope requires it),
  `ServiceScopeGrants` (immutable copy; `allows(caller, scope)`).
- `application.command.IssueServiceTokenCommand`, `application.result.IssueServiceTokenResult`
  (`Issued` with redacted `toString`, `ScopeNotAllowed`, `BusinessReferenceRequired`),
  `application.port.in.IssueServiceTokenUseCase`, `application.port.out.gateway.ServiceTokenSigner`,
  `application.service.ServiceTokenSettings` (issuer, audience, lifetime) and `IssueServiceTokenService`
  (grant → reference → claims → sign; no I/O besides the signer).
- Tests: `ServiceScopeTest`, `ServiceTokenClaimsTest`, `IssueServiceTokenServiceTest`.

Turn 2 (done):
- `infrastructure.adapter.out.jose.NimbusServiceTokenSigner` — ES256 under the private P-256 key (must carry `kid`),
  `typ=service-token+jwt`, exactly the claims of `ServiceTokenClaims` (`businessReference` only when present).
- `rest.common.ServiceClientAssertionVerifier` — key looked up by the service the assertion names (`iss` = `sub`),
  header `kid` must be that key's; same header/claim/lifetime checks as `BffAssertionVerifier`.
  `ServiceClientAssertionFilter` gates only `POST /internal/v1/service-tokens` (the JWKS `GET` is open) and leaves
  `VerifiedServiceClient` on the request (named `VerifiedServiceCaller` until 2026-11-04, see below).
- `valkey.UsedAssertionKeys` (interface) with `BffAssertionKeys` and `ServiceClientAssertionKeys`
  (`service-client-assertion:used:v1:<sha256(jti)>`) sharing the package-private `AssertionIdDigest`;
  `ValkeyAssertionReplayStore` takes the interface, one instance per kind of assertion.
- Tests: `NimbusServiceTokenSignerTest`, `ServiceClientAssertionVerifierTest` (every negative case of the BFF test
  mirrored, plus `iss` ≠ `sub`, unknown service, the BFF's `typ`), `ServiceClientAssertionFilterTest`,
  `UsedAssertionKeysTest` (frozen vectors for both prefixes); `TestServiceClientAssertions` plays the onboarding service.

Turn 3 (done):
- `rest.controller.ServiceTokenController` (`POST /internal/v1/service-tokens`, caller from the filter's request
  attribute) and `ServiceTokenJwksController` (`GET …/jwks`, bare RFC 7517 document from `rest.common.ServiceTokenPublicKeys`,
  prepared at startup; the one route without the envelope). `IssueServiceTokenRequest` / `ServiceTokenResponse`
  (token redacted in `toString`), `ServiceTokenRestMapper` (`Issued` → 200, `ScopeNotAllowed` → 403 `SCOPE_NOT_ALLOWED`,
  `BusinessReferenceRequired` → 400 `REQUEST_REJECTED`, unknown scope code → 400).
- `ServiceTokenProperties` (`enabled`, `issuer`, `audience`, `lifetime` required and 1–30 min, `signing-private-jwk`,
  `callers.<service>.{public-jwk, scopes}`) and `ServiceTokenConfiguration` (settings, grants, signer, JWKS document,
  verifier, filter with its own `ValkeyAssertionReplayStore` on `ServiceClientAssertionKeys`, use case, mapper; a bad key,
  an unknown scope or a malformed service ID stops startup naming the setting). `application.yaml` block,
  `ErrorCodes.SCOPE_NOT_ALLOWED` with vi/en messages.
- Tests: `ServiceTokenRestMapperTest`, `ServiceTokenControllerTest` (`@WebMvcTest`: envelope, status table, body
  validation, bare JWKS), `ServiceTokenConfigurationTest` (flag off = no beans; lifetime required and bounded; bad signing
  key, bad caller key, missing `kid`, unknown scope, malformed service ID each fail naming the setting);
  `ApplicationBootIT` gains a scenario: assertion → token, token verifies against the JWKS route with the expected claims,
  the same assertion is `401` on reuse, no assertion is `401`, scope without reference is `400`.
- README (route table, slice paragraph, configuration rows, known-gaps line) and ARCHITECTURE decisions log.

Turn 4 (done):
- `SecurityEventType.SERVICE_TOKEN_ISSUED` / `SERVICE_TOKEN_REFUSED` with `aboutAService()`; reasons `TOKEN_ISSUED`,
  `SCOPE_NOT_GRANTED`, `BUSINESS_REFERENCE_MISSING` (names frozen in `DomainEnumCodesTest`).
- `SecurityAuditEvent` carries two shapes on one row: a login event needs `channel`, a service-token event needs
  `serviceId` + `scope` (+ `tokenId` when issued); the compact constructor enforces whichever the reason's type asks for.
  Never the token or the business reference.
- `V6__audit_service_token.sql` (source `authentication-service-src/docs/db-phases/phase-audit-service-token.sql`):
  `CHANNEL` nullable, `SERVICE_ID`, `SCOPE` (wire code), `TOKEN_ID`, `IX_SAE_SERVICE_TIME`. Entity and mapper follow.
- `IssueServiceTokenService` hands each decision to `SecurityAuditStore` after deciding (six dependencies now: four
  collaborators plus the token-ID supplier and the clock). Config injects the store, which always exists (disabled = forgets).
- Tests: `SecurityAuditEventTest` (shape rule), `IssueServiceTokenServiceTest` (an event per branch),
  `SecurityAuditEventPersistenceAdapterIT` (service-token rows on V6), `ServiceTokenConfigurationTest` (audit wiring),
  `ApplicationBootIT` (issued and refused decisions land in `SECURITY_AUDIT_EVENT` with the token's `jti`).

## Renamed 2026-11-04 (names say the role, rule N09)

Behavior unchanged; token claims (`sub`), request JSON and the `auth.service-token.callers` setting are unchanged.

- `IssueServiceTokenCommand.caller` and `ServiceScopeGrants.allows(caller, …)` → `callingService`.
- `ServiceTokenClaims.caller` → `issuedTo` (rendered as `sub`).
- `VerifiedServiceCaller(caller)` → `VerifiedServiceClient(serviceId)`, under
  `ServiceClientAssertionFilter.CALLING_SERVICE_ATTRIBUTE` (a type ending in `Service` must be an application
  service, so the type is not called `VerifiedCallingService`).
- `ServiceClientAssertionVerifier`: `VerifiedClientAssertion.clientService`, `clientKeys` / `clientKey`.
- `mvn -o verify`: 336 unit tests, 37 ITs.

## Not in this slice

- The BFF does not verify these tokens yet (`mobile-bff` has `NimbusJwtDecoder.withJwkSetUri` tooling but no
  service-token route guard).
- mTLS / workload identity for the caller, key rotation beyond "publish then sign", proof of possession for the
  app-held token, and caller authentication for the other `/internal` routes.
