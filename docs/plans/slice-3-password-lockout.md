# Slice 3 — password lockout and CAPTCHA (DB phase 2)

Status: **implemented 2026-10-25** (turns 1–3; see README for the test run). CAPTCHA = server-generated image; counter keeps counting after an expired lock; unlock endpoint included. Schema: `phase-2-password-lockout.sql`
(three columns on `CUSTOMER_AUTHENTICATION`). Policy decided in chat 2026-10-25; the DD docs left it
open ("Auth lockout vs Keycloak brute-force", "CAPTCHA after three failures — contract pending").

## Policy (your decisions)

| Consecutive failures on one identity | Effect |
|---|---|
| 1 | `401 INVALID_CREDENTIALS` |
| 2 | `401 INVALID_CREDENTIALS`; from now on a login for this customer must carry a solved CAPTCHA |
| 3 | `PASSWORD_STATUS=LOCKED`, `PASSWORD_LOCKOUT_TIME = now + 15 min` → `423 ACCOUNT_LOCKED` |
| 4 (after the 15-min lock expired) | `LOCKED`, lockout time `now + 24 h` |
| 5 | `PASSWORD_STATUS=PERMANENTLY_LOCKED` — only the bank can unlock |

- The counter resets to 0 (and CAPTCHA is no longer required) only on a **successful** login.
  A lock that expires does **not** reset it: the next failure escalates.
- While locked (temporary not yet expired, or permanent) the password is **not** sent to
  Keycloak: `423 ACCOUNT_LOCKED`, no remaining time in the body. Keycloak's own brute-force
  detector stays as an independent second layer.
- Unknown user names are not counted (no row) and still get `401 INVALID_CREDENTIALS`.
- Status and lockout time are always written together (README rule), with `… AND VERSION = ?`
  because two failures can arrive at the same moment (README "code needed first").

## CAPTCHA (needs your confirmation, see questions)

- `POST /api/ns/v1/login/captcha {userName}` → `200 {captchaId, image}` (PNG, base64, 5 distorted
  characters, generated with the JDK's `java.awt` in headless mode — no external provider yet).
  The same shape is returned for an unknown user so the endpoint cannot probe accounts.
- The challenge is stored in Valkey: `captcha:v1:<captchaId>` HASH `{customerId, answerHash, expiresAtMs}`,
  TTL 5 min, deleted on first use (`WATCH`/`MULTI` like sessions). `answerHash` = HMAC of the
  upper-cased answer with the session HMAC key, so a Valkey copy does not reveal answers.
- `LoginRequest` gets optional `captcha {captchaId, answer}`. When the identity has ≥ 2 failures
  and no valid captcha bound to that customer is supplied → `428 CAPTCHA_REQUIRED` **without**
  consuming a password attempt and without calling Keycloak. A wrong captcha answer also returns
  `428` and burns the challenge.
- Nothing about CAPTCHA is stored in MySQL; "required" is derived from `PASSWORD_FAILED_COUNT >= 2`.

## Unlock (needs your confirmation)

`POST /internal/v1/customers/{customerId}/password-unlock` — bank staff tooling resets
`PASSWORD_STATUS=ACTIVE`, count 0, lockout time null. Internal, no caller auth yet (same as the
other `/internal` routes). Returns `204`, `404` when unknown.

## Code

- `V2__password_lockout.sql` = phase-2 file unchanged. `CustomerAuthenticationEntity` gains the
  three columns; `ddl-auto=validate` keeps them honest.
- `domain.model`: `PasswordLockout` value (status, failedCount, lockedUntil) with the pure rules:
  `isLocked(now)`, `afterFailure(now, policy)`, `reset()`, `captchaRequired()`;
  `LockoutPolicy` record (captchaAfter=2, locks = {3: PT15M, 4: PT24H}, permanentAt=5) from config.
  `CustomerAuthentication` (port.out value) carries the `PasswordLockout` and a `version`.
- `application.port.in`: `LoginResult` gains `AccountLocked`, `CaptchaRequired`;
  `IssueCaptchaUseCase` / `IssueCaptchaCommand(userName)` / `CaptchaChallenge(id, imagePng)`;
  `UnlockPasswordUseCase`.
- `application.port.out`: `CustomerAuthenticationRepository` gains `recordFailure(identity, lockout)`
  and `resetLockout(identity)` (CAS on version, return the stored row), `unlock(customerId)`;
  `CaptchaStore` (`save`, `consume(captchaId, customerId) → boolean`); `CaptchaGenerator`
  (`next() → (answer, png)`).
- `application.service`: `LoginService` checks lockout → captcha → Keycloak → record outcome;
  `CaptchaService`; `PasswordUnlockService`.
- Adapters: persistence (entity columns, `CustomerAuthenticationPersistenceAdapter` writes),
  `adapter.out.valkey.ValkeyCaptchaStore` + `CaptchaKeys`, `adapter.out.captcha.AwtCaptchaGenerator`,
  web: `CaptchaController` (`/api/ns`), `PasswordUnlockController` (`/internal`), DTOs, mappers,
  error codes `ACCOUNT_LOCKED`, `CAPTCHA_REQUIRED` in vi/en.
- Tests: `PasswordLockoutTest` (every escalation step, expiry does not reset), `LoginServiceTest`
  additions (short-circuit, captcha gate, reset on success, concurrent failure CAS → re-read),
  `CaptchaServiceTest`, persistence IT (phase-2 columns, CAS), `ValkeyCaptchaStoreIT`,
  `@WebMvcTest` (423/428, captcha endpoint), boot IT extended (2 failures → captcha → lock → unlock).

## Turns

1. Domain (`PasswordLockout`, `LockoutPolicy`), port changes, `LoginService` lockout path, V2
   migration + entity + persistence adapter writes, persistence IT, error codes. `mvn -o verify`.
2. CAPTCHA: generator, Valkey store, service, endpoint, login gate, tests.
3. Unlock endpoint, web wiring for new results, boot IT extension, README/ARCHITECTURE notes.
