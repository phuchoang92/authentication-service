# Slice 13 — the device proves its key at login (option A, 2026-11-03)

Status: **decisions 1–4 taken 2026-11-03 (one signing key; ML-DSA-65); turn 1 implemented 2026-11-03**, turns 2–4
pending. Nothing committed. The proof is off by default (`auth.login.device-proof-required=false`), so no
environment changes behaviour until it is switched on.

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
| 4 | Key type | **ML-DSA-65** (FIPS 204), decided 2026-11-03: signed and verified with the JDK 25 `Signature` API (no library); CryptoKit `MLDSA65` (iOS 26) and Bouncy Castle 1.86 `MLDSASigner` on the apps. Checked on JDK 25.0.2 before coding: keygen/sign/verify work, public key 1952 bytes (SPKI 1974), signature 3309 bytes, verify ≈0.4 ms; the FIPS 204 context string is not exposed, so both sides sign with an empty context. Nimbus has no ML-DSA, so the JWS is parsed by Auth itself. Not yet cross-checked with CryptoKit or BC (turn 2). |

## Contract (proposed, mirrors the DD reference README one-shot Kdev proof)

Login, MOBILE channel, both fields required (WEB sends neither):

```json
{ "userName": "...", "password": "...", "channel": "MOBILE", "deviceId": "...", "platform": "ANDROID",
  "devicePublicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "deviceProof": "<compact JWS>",
  "tokenEncryptionKey": { ... } }
```

`devicePublicKey`: `{"alg":"ML-DSA-65","kty":"AKP","pub":"<1952 bytes base64url>"}` (JOSE form of
draft-ietf-cose-dilithium); Auth keeps its canonical text (exactly those three members, in that order) and its
thumbprint = base64url(SHA-256(canonical text)), ≈2.7 KB, hence migration V6 (`PRIMARY_PUBLIC_KEY` → 4096).

`deviceProof`: compact JWS ≈7.3 KB; header exactly `{alg:"ML-DSA-65", typ:"bank-login-device-proof+jwt", kid:<thumbprint>}`;
claims exactly `{v:1, purpose:"LOGIN_DEVICE_PROOF", userName, channel, deviceId, platform, tokenKeyJkt, iat, exp, jti}`
(`tokenKeyJkt` = RFC 7638 thumbprint of `tokenEncryptionKey`); signature over the ASCII signing input with an empty
FIPS 204 context; `exp − iat ≤ 120 s`, 5 s skew; `jti` ≤ 128 chars, used once: Valkey `login-proof:used:v1:<SHA-256(jti)>`
until `exp + skew` (`ValkeyAssertionReplayStore` with `LoginProofKeys`). The signature is checked against the **sent**
key; the sent key is then compared with the stored one.

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

1. **Done 2026-11-03.** Domain: `DeviceSigningKey` (canonical JWK + thumbprint), `DeviceKeyClaim`
   (Proven / Unproven / None — what a login says about the key), `Session.deviceKey` on restricted sessions,
   `TrustedDevice.hasKey`. Application: ports `DeviceProofVerifier` (pure) and `LoginProofReplayStore`,
   `DeviceProofBindings`; `LoginCommand.deviceProof`; `LoginResult.DeviceProofRejected`;
   `SecurityEventReason.DEVICE_PROOF_REJECTED` (LOGIN_REFUSED); `LoginService` checks the proof before any lookup
   and only when `deviceProofRequired`; `TrustedDeviceService.routeAfterPassword(…, DeviceKeyClaim, …)` with the
   routing table above (a row without a key never matches a proven key); `SessionService.issueRestricted(…, key)`.
   Adapters, so the build stays green with the proof wired: `MlDsaDeviceProofVerifier` (JDK `Signature`, strict
   JWS/JWK parsing), `LoginProofKeys` + the existing `ValkeyAssertionReplayStore`, `LoginRequest.deviceProof`
   (≤ 8192), `400 DEVICE_PROOF_REJECTED`, `LoginProperties.deviceProofRequired` (default false), `SessionHashCodec`
   fields `deviceKeyJwk`/`deviceKeyJkt` (both or neither), V6. Tests: `LoginServiceTest` (+5: proven first device,
   missing/forged/other-key/replayed proof refused before Keycloak with no lockout count and an audit row, primary with
   another key → restricted session carrying the new key, replay store down → unavailable, enforcement off keeps the
   old behaviour), `TrustedDeviceServiceTest` (+2), `SessionHashCodecTest` (+1), `MlDsaDeviceProofVerifierTest`
   (5: real ML-DSA-65 keys signed with the JDK; canonical key; other key / other login / tampered; exact header and
   claim set; lifetime; key shape). `TrustedDevice.publicKey` stays nullable: rows written before this slice.
2. **Enforcement and interop.** Switch `device-proof-required` on in the login ITs: login with a correct proof →
   ACTIVE; replayed `jti` → 400; primary device with another key → NEED_TRUSTED_DEVICE; the proof-size request still
   fits the body limit. Cross-check the JWS profile with CryptoKit `MLDSA65` (macOS 26 tool next to `dcp_hpke`) and
   Bouncy Castle 1.86 `MLDSASigner`: a vector file with a key, a proof and the expected thumbprint, pinned in
   `src/test/resources`. `PRIMARY_CRYPTO_SUITE` gets a value for ML-DSA rows.
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
- ES256 device keys as an alternative (the port allows one; nothing is built for it); mTLS between BFF and Auth; the
  BFF changes to forward `deviceProof` and `devicePublicKey` unchanged.
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
