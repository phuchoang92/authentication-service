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
| 4 | Key type | **ML-DSA-65** (FIPS 204), decided 2026-11-03: signed and verified with the JDK 25 `Signature` API (no library); CryptoKit `MLDSA65` (iOS 26) and Bouncy Castle 1.86 `MLDSASigner` on the apps. Checked on JDK 25.0.2 before coding: keygen/sign/verify work, public key 1952 bytes (SPKI 1974), signature 3309 bytes, verify ≈0.4 ms; the FIPS 204 context string is not exposed, so both sides sign with an empty context. Raw signature, no JOSE (decided the same day: Nimbus and CryptoKit have no ML-DSA JWS, and `alg` on the wire is a liability). Not yet cross-checked with CryptoKit or BC (turn 2). |

## Contract (decided 2026-11-03 after turn 1; supersedes the first draft)

Three further decisions by the owner, taken the same day: **a login never trusts a device** (the first device
goes through enrollment like any other; `trustFirstDevice` and the slice-4 direct path are gone), **the device
key never travels at login** (it is sent once, at `init` of the enrollment API, and verified from the stored
row), and **the proof is a raw signature, not a JWS** (no `alg`/`kid`/`typ` on the wire; the stored key's suite
decides). The channel, installation and proof travel as **headers**, the body keeps the credentials and the
token key:

```http
POST /api/ns/v1/login
X-Channel: MOBILE
X-Device-Id: <installation id>
X-Device-OS: ANDROID | IOS
X-Device-Proof: <issuedAt epoch seconds>.<nonce 16–64 base64url>.<signature base64url>
Content-Type: application/json

{ "userName": "...", "password": "...", "tokenEncryptionKey": { ... }, "captcha": { ... }? }
```

Signed bytes (both sides): each field as 4-byte big-endian length + UTF-8, in order
`DCP-LOGIN-DEVICE-PROOF-V1`, userName, channel, deviceId, platform, RFC 7638 thumbprint of `tokenEncryptionKey`,
`issuedAt` (decimal), nonce. Algorithm ML-DSA-65 (FIPS 204), empty context; the stored key is the JWK
`{"alg":"ML-DSA-65","kty":"AKP","pub":<1952 bytes base64url>}` the app sent at enrollment `init`. `issuedAt` at most
120 s old, 5 s skew; nonce used once (`login-proof:used:v1:<SHA-256(nonce)>` until `issuedAt + 125 s`). Header
budget: `server.max-http-request-header-size: 16KB` (the signature alone is 4.4 KB base64url; BFF/gateway limits
must allow it too). A malformed header is `400 REQUEST_REJECTED`; a proof that does not verify is **not** an error.

| Device state after the password | Proof (when enforced) | Routing |
|---|---|---|
| WEB | — | FULL session |
| No live row, PENDING, trusted but not primary, expired | not asked | NEED_TRUSTED_DEVICE (as before) |
| Trusted primary | verifies under the row's key, bound to this login, nonce first use | FULL session, last login recorded |
| Trusted primary | missing, wrong, replayed, or the row has no key | NEED_TRUSTED_DEVICE (reinstall / copied device ID: trust again with FACE) |

With `device-proof-required=false` a trusted primary is taken at its word (the pre-slice behaviour).

## Turns

1. **Done 2026-11-03 (revised the same day to the contract above).** Domain: `DeviceProof` (issuedAt, nonce,
   signature). Application: ports `DeviceProofVerifier` (`verify(storedPublicJwk, proof, bindings)`, pure) and
   `LoginProofReplayStore`; `DeviceProofBindings`; `LoginCommand.deviceProof`; `TrustedDeviceService.routeAfterPassword(…,
   DevicePossession, …)` with the routing table above and **no first-device trust** (`TrustedDeviceRepository.trustFirstDevice`
   and `TrustFirstResult` removed from the port, the JPA adapter and the in-memory double); `LoginService` builds the
   possession check (enforced: verifier under the row's key + nonce first use; replay store down → unavailable).
   Adapters: `MlDsaDeviceProofVerifier` (JDK `Signature`, length-prefixed signing input, strict stored-JWK parsing),
   `LoginProofKeys` + `ValkeyAssertionReplayStore`, `DeviceHeaders` + `LoginRestMapper.toCommand(HttpHeaders, body)`
   (channel/device/OS/proof from headers, shape-checked → `400`), `LoginRequest` without device fields,
   `LoginProperties.deviceProofRequired` (default false), `server.max-http-request-header-size=16KB`, V7
   (`PRIMARY_PUBLIC_KEY` → 4096). Tests: `LoginServiceTest` (5 proof tests: full with a proof used once / replay →
   restricted; missing or forged proof → restricted with no lockout count; row without key; replay store down →
   unavailable; enforcement off / WEB), `TrustedDeviceServiceTest` (routing rewritten: a login never registers; primary
   proves or waits; non-primary is not asked), `MlDsaDeviceProofVerifierTest` (5, real ML-DSA-65 keys signed with the
   JDK; signing-input layout pinned), `LoginRestTest` (headers; proof header parsed; bad header → 400), boot and
   persistence ITs seed the trusted primary row directly. The earlier turn-1 pieces this replaced (`DeviceSigningKey`,
   `DeviceKeyClaim`, `Session.deviceKey`, `LoginResult.DeviceProofRejected`, the JWS verifier) are deleted.
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
