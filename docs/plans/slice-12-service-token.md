# Slice 12 — scoped service token for flows without a customer session

Status: **turns 1–2 implemented 2026-11-03** (turn 1: domain + application; turn 2: signer, client-assertion verifier and
filter, replay key factory; `mvn -o verify`: 310 unit tests, 37 ITs); turns 3–4 pending. Nothing committed.

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
  `VerifiedServiceCaller` on the request.
- `valkey.UsedAssertionKeys` (interface) with `BffAssertionKeys` and `ServiceClientAssertionKeys`
  (`service-client-assertion:used:v1:<sha256(jti)>`) sharing the package-private `AssertionIdDigest`;
  `ValkeyAssertionReplayStore` takes the interface, one instance per kind of assertion.
- Tests: `NimbusServiceTokenSignerTest`, `ServiceClientAssertionVerifierTest` (every negative case of the BFF test
  mirrored, plus `iss` ≠ `sub`, unknown service, the BFF's `typ`), `ServiceClientAssertionFilterTest`,
  `UsedAssertionKeysTest` (frozen vectors for both prefixes); `TestServiceClientAssertions` plays the onboarding service.

Turn 3: `ServiceTokenController`, `ServiceTokenJwksController` (public-key document prepared in `rest.common`, no use
case), request/response DTOs, `ServiceTokenRestMapper`; `ServiceTokenConfiguration` / `ServiceTokenProperties`
(flag, issuer, audience, lifetime bounds, signing key with `kid`, callers map); `ErrorCodes.SCOPE_NOT_ALLOWED` +
messages; `application.yaml`; `ApplicationBootIT` scenario (mint an assertion with a test key, get a token, verify it
against the JWKS route, `403` for an ungranted scope, `401` for a replayed assertion); README and ARCHITECTURE notes.

Turn 4 (after slice 9 is committed): `SecurityEventType.SERVICE_TOKEN_ISSUED` / `SERVICE_TOKEN_REFUSED`, V6 additive
migration (nullable `CHANNEL`, `SERVICE_ID`, `SCOPE`, `TOKEN_ID`), one `record` call per branch in the service.

## Not in this slice

- The BFF does not verify these tokens yet (`mobile-bff` has `NimbusJwtDecoder.withJwkSetUri` tooling but no
  service-token route guard).
- mTLS / workload identity for the caller, key rotation beyond "publish then sign", proof of possession for the
  app-held token, and caller authentication for the other `/internal` routes.
