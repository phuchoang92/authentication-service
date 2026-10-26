# Slice 7 — self-describing session token `s1:auth:session:<channel>:<sessionId>:<secret>`

Status: **implemented 2026-10-26** (both turns landed in one, since the REST pieces were needed to compile; see README for the test run). Replaces the HMAC-keyed opaque token `k1.<43>` and the
`session:v1:k1:<HMAC(token)>` Valkey key of slice 2 with a token the BFF can resolve without a shared key.
Nothing about the session is hashed or hidden in this slice: the key names channel and session ID, and the HASH
holds the secret in clear.
No SQL change. The JWE envelope, the restricted session, enrollment and approval flows are unchanged.

## Decisions (2026-10-26)

| Topic | Decision |
|---|---|
| Token | `s1:auth:session:<channel>:<sessionId>:<secret>` — `s1` format version, `channel` = `MOBILE` / `WEB`, `sessionId` = the UUID Auth generates, `secret` = 32 random bytes as unpadded base64url (43 chars) |
| Who holds it | the app, inside the JWE envelope as today; the BFF forwards it unchanged to Auth on `/api/**` (no BFF-signed assertion) |
| Valkey key | `session:v1:<channel>:<sessionId>` — channel and session ID are not hidden; no HMAC key anywhere |
| Secret check | the HASH stores the `secret` **in clear** (decision: no hashing or hiding of the session yet); a reader (BFF or Auth) compares the presented secret with the stored one in constant time; a mismatch is "no session". Hashing the stored secret is a later hardening step, not part of this slice |
| Restricted sessions | same format and key; the HASH field `status` (`ACTIVE` / `NEED_TRUSTED_DEVICE`) tells them apart, and the BFF refuses a restricted session on banking routes after reading the HASH |
| Extend (BFF) | `POST /internal/v1/sessions/extend` takes `sessionLookup{channel, sessionId}`; the BFF never sends the secret there; Auth re-reads the HASH as today |
| CAPTCHA answers | were HMAC-ed with the session lookup key; they get their own key `auth.captcha.answer-hmac-key-base64` (≥ 32 bytes); the Valkey key `captcha:v1:<uuid>` is unchanged |
| Removed settings | `auth.session.lookup-key-version`, `auth.session.lookup-hmac-keys-base64` |

## Changes

- `domain.model.OpaqueToken`: parsed value `(channel, sessionId, secret)`, format
  `s1:auth:session:(MOBILE|WEB):<uuid>:[A-Za-z0-9_-]{43}`, `toString` redacted (`s1:auth:session:MOBILE:<id>:redacted`);
  `OpaqueTokenGenerator.next(channel, sessionId)`; `RandomOpaqueTokenGenerator` builds the secret.
- `application.port.out.model.SessionLookup(channel, sessionId)`; `StoredSession` unchanged; `SessionStore.findByToken` fails
  closed when the secret does not match.
- `application.command.ExtendSessionCommand(channel, sessionId, admittedAt, routeId, admissionId)`.
- `valkey.SessionKeys`: no HMAC, `forLookup(lookup)` → `session:v1:<channel>:<sessionId>`, `lookupOf(token)`;
  `SessionHashCodec` gains the required field `secret`; `ValkeySessionAdapter.create` stores it, `findByToken` compares it
  (constant time) and answers empty on a mismatch.
- `valkey.CaptchaKeys` fed from `auth.captcha.answer-hmac-key-base64` (`CaptchaProperties`, validated in `ValkeyConfiguration`).
- REST: `SessionFilter` parses the new Bearer format; `ExtendSessionRequest.SessionLookupDto(channel, sessionId)` with validation;
  `SessionRestMapper` adjusted; `LoginService` and `DeviceApprovalService`/`DeviceEnrollmentService` pass channel + session ID to the
  token generator.
- Config: `SessionProperties` drops the key settings; `application.yaml` and README configuration table updated.
- Tests: `OpaqueTokenTest`, `SessionKeysTest` (new frozen key vector), `SessionHashCodecTest` (`secret`), `ValkeySessionAdapterIT`
  (wrong secret → empty), `SessionServiceTest`, `LoginRestTest`, `ApplicationBootIT` (no HMAC; extend by channel + session ID; the
  token parsed from the envelope), `LoginConfigurationTest`/`ValkeyConfiguration` settings, in-memory `InMemorySessionStore`.
- Docs: README (token, Valkey key, configuration), ARCHITECTURE "Current" note, memory note.

## Turns

1. Domain + application + Valkey adapter + config + tests; `mvn -o verify`.
2. REST (filter, extend DTO), boot IT, docs; `mvn -o clean verify`.
