# Slice 13 — the device proves its key at login (option A, 2026-11-03)

Status: **plan, not approved**. Nothing implemented.

## Context

- `LoginService` → `TrustedDeviceService.routeAfterPassword` decides FULL vs NEED_TRUSTED_DEVICE from
  `(customer, channel, deviceId)` alone. `LoginRequest.devicePublicKey` is only stored when the customer's
  first device is trusted directly; for a known device it is ignored. A copied `deviceId` plus the password
  gives the primary device's ACTIVE session.
- The key a device proves at enrollment (`verify`, challenge decrypted with the device key) is never used
  again except when the same device enrolls again. DD 00 defines a trusted device as "MFA + possession of
  Kdev"; today possession is checked once, at enrollment, never at login.
- DD 06 and DD 20 §6 decide `deviceProof` = ES256 by Kdev **[ĐÃ CHỐT]**. The App sample doc §2 says the
  opposite ("không yêu cầu proof"). The sample doc also made the device key an X-Wing key (`clientPublicKey`),
  which cannot sign. This slice resolves that: Kdev is a **signing** key; encryption keys are never stored.

## Decisions to take before coding

| # | Decision | Recommendation |
|---|---|---|
| 1 | **One key, two uses** (P-256 signs ES256 at login and receives the ECDH-ES challenge at enrollment, as the current contracts imply) **or one signing key** (Kdev ES256; the enrollment challenge is answered by a JWS, not by decrypting a JWE) | **One signing key.** A key used for both signing and key agreement is a hygiene exception we would carry for years; a signing-only Kdev also survives the later move of encryption to X-Wing untouched. |
| 2 | Enrollment `init`/`verify` shape under decision 1 | Keep the three steps and Ksrv (Ksrv is **[ĐÃ CHỐT]** for Smart OTP; still dropped at confirm until phase 5). `init` returns `serverPublicJwk` and a plain `challenge` (32 random bytes, base64url); `verify` takes `challengeProof`: compact JWS by Kdev, `typ=trusted-device-challenge-proof+jwt`, claims `{enrollmentId, challenge, serverKeyJkt, iat, exp}`. Removes `NimbusChallengeSealer.sealChallenge/openResponse`. **Changes DD 20 §4/§6a and the App doc §3** — needs the owner's sign-off. |
| 3 | Where the login proof is verified relative to the password | Signature, time window and `jti` **before** Keycloak (cheap, no lockout count: `400 REQUEST_REJECTED`); key-vs-stored-key **after** the password, inside routing. An invalid proof never degrades to "new device" (DD reference README). |
| 4 | Key type | ES256 (P-256) now, as DD 06. ML-DSA-65 (JDK 25, CryptoKit iOS 26, BC 1.86) is possible later behind the same port; not in this slice, not cross-checked. |

## Contract (proposed, mirrors the DD reference README one-shot Kdev proof)

Login, MOBILE channel, both fields required (WEB sends neither):

```json
{ "userName": "...", "password": "...", "channel": "MOBILE", "deviceId": "...", "platform": "ANDROID",
  "devicePublicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "deviceProof": "<compact JWS>",
  "tokenEncryptionKey": { ... } }
```

`deviceProof`: header `alg=ES256`, `typ=bank-login-device-proof+jwt`, `kid` = RFC 7638 thumbprint of
`devicePublicKey`, no `jwk`/`jku`/`x5*`/`crit`; claims exactly `{v:1, purpose:"LOGIN_DEVICE_PROOF", userName,
channel, deviceId, platform, tokenKeyJkt, iat, exp, jti}`; `exp − iat ≤ 120 s`, 5 s skew; `jti` unique, kept in
Valkey `login-proof:used:v1:<SHA-256(jti)>` until `exp + skew` (same pattern as `ValkeyAssertionReplayStore`).
The signature is checked against the **sent** key; the sent key is then compared with the stored one.

| Device state after the password | Sent key vs stored key | Routing |
|---|---|---|
| No live device for the customer on the channel | — | trust first device **with this proven key** (as today, but the key is now required and proven) |
| Known live device, trusted, primary | equal | FULL session |
| Known live device, trusted, primary | different | NEED_TRUSTED_DEVICE (reinstall: DD 20 "key khác → trust lại"); the restricted session records the new key's thumbprint |
| Known device, not primary / expired / PENDING | any | NEED_TRUSTED_DEVICE (as today) |
| Unknown device | — | NEED_TRUSTED_DEVICE (as today) |

The restricted session carries `deviceKeyJkt` of the key proven at login. `init` (primary enrollment) and
`request` (approval) no longer take a key: they use the key the session proved, and the trust commit stores it.
A known device "keeping its old key" therefore means: it logged in with that key.

## Turns

1. **Domain + application.** `DeviceProof` value (parsed, verified claims; never the JWS text);
   `DeviceProofVerifier` port (`verify(jws, expected: userName, channel, deviceId, platform, tokenKeyJkt, now)`
   → `Verified(publicJwk, jkt, jti, exp)` | rejection); `LoginProofReplayGuard` port (`claim(jti, until)`).
   `LoginCommand` gains `deviceProof`, requires it with `devicePublicKey` on MOBILE. `LoginService`: verify
   proof before `credentialVerifierPort`; `TrustedDeviceService.routeAfterPassword` takes the proven key and
   compares thumbprints (table above); `Session` (restricted) gains `deviceKeyJkt` + `deviceKeyJwk`.
   `TrustedDevice` keeps `publicKey` but it becomes required on every row that is trusted (nullable only for
   history rows written before this slice). Unit tests: proof accepted / wrong signature / wrong claims /
   expired / replayed / key mismatch on the primary → NEED_TRUSTED_DEVICE / first device stores the proven key.
2. **Adapters.** `NimbusDeviceProofVerifier` (strict header, exact claim set, ES256 only — reuse the strictness
   of `BffAssertionVerifier`), `ValkeyLoginProofReplayStore` (`SET NX`), `LoginRequest.deviceProof`
   (`@Size(max = 4096)`), REST mapper, `400 REQUEST_REJECTED` for a bad proof (no lockout, no KC call), test
   vector: a JWS made with the DD reference Kdev key (`password-one-shot-vectors.json`, `Kdev`) so the claim
   profile is pinned. IT: login with a correct proof → ACTIVE; replayed `jti` → 400; primary device with another
   key → NEED_TRUSTED_DEVICE.
3. **Enrollment and approval use the proven key** (decision 2). `InitEnrollmentRequest` loses
   `devicePublicJwk`; `init` seals nothing: returns `serverPublicJwk` + plain `challenge`; `verify` takes
   `challengeProof` (JWS by the session's key, claims above, `serverKeyJkt` binds Ksrv). `EnrollmentTransaction`
   keeps `serverPrivateJwk` (Ksrv, for phase 5) and `devicePublicJwk` (from the session). `RequestApprovalRequest`
   loses `devicePublicJwk`. `ChallengeSealer` → `ChallengeProofVerifier`; `NimbusChallengeSealer` deleted.
   Tests: DeviceEnrollmentService (proof by another key, wrong enrollmentId, wrong Ksrv jkt), controller, IT.
4. **Docs.** DD 20 §4 (challenge is signed, not sealed; key proven at login), §6a (login `deviceProof`,
   `init`/`verify` bodies), App sample doc §2 (login sends `devicePublicKey` + `deviceProof`; `clientPublicKey`
   removed from init; X-Wing stays for `X-Client-Encryption-Public-Key` only — the rebuild still uses P-256 JWE for
   the token envelope, so the doc marks X-Wing there as target, not implemented), `ARCHITECTURE.md` §6.1 (routing
   inputs). Memory note for the decision.

Each turn ends with `mvn -o verify` green (baseline after slice 12 turn 2: 310 unit tests, 37 ITs) and the
docs/plans status line updated.

## Not in this slice

- X-Wing for the token envelope or the enrollment challenge (the rebuild uses P-256 JWE; `libs/dcp-hpke-xwing`
  is not wired into this tree). With a signing-only Kdev that migration touches no stored key.
- Persisting Ksrv for Smart OTP (phase 5) and who verifies Smart OTP (DD 20 [MỞ]).
- ML-DSA device keys; mTLS between BFF and Auth; the BFF changes to forward `deviceProof` unchanged.
- The approval flow's second MFA; it only stops taking a key at `request`.

## Risks

- Every mobile login now needs the App to sign: the App teams must implement the JWS before this slice is
  enabled on an environment they use. Until then MOBILE logins without a proof are rejected — gate with
  `auth.device.login-proof-required` (default true in tests, set explicitly per environment).
- Reinstalled Apps lose the key and go through enrollment with FACE on every reinstall: intended (DD 20),
  but it is the behaviour the owner earlier wanted to avoid ("point 1"). This slice makes it explicit rather
  than silent.
- Two contracts marked [ĐÃ CHỐT] change (sealed challenge → signed challenge; login proof present). Both are
  recorded in DD 20 with the date if approved.
