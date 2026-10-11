# Authentication Service v1 — G1 complete, G2 in progress

This is the isolated, clean-build G1 source tree, renamed from `authentication-service-rebuild` after the old project was removed. It is not connected to the running database, Redis, deployment, or Maven reactor. The design input is `../docs/DD/target` and the coding authority is `../docs/authentication-documentation/docs/design-v1/code-design-rules-and-patterns.md`.

## What G1 provides

- Standalone Spring Boot 4.1.1 / Java 25 / Maven wrapper 3.9.11, one Maven module under `com.vpbank.dcp`.
- JDK-only `core` ports and values; Spring/HTTP/JPA/Redis/JOSE implementations in `infrastructure`.
- Strict JSON parsing, safe public errors, redacted secret-bearing values, configured public URI, inbound mTLS URI-SAN filter, outbound TLS 1.3 client identity/trust factory.
- Pinned biometric Keycloak context verifier, DPoP verifier, typed enrollment JWS verifier, JWE envelope inspector, JCS command digest and signing-input codec. Password now travels through authenticated TLS to standard Keycloak Direct Grant; OTP remains an MFA-recipient JWE. Auth never decrypts OTP JWE.
- Fresh MySQL 8.4 Flyway schema (21 `auth_` tables), a focused EntityManager CAS adapter for the authority-control fence, and short transaction tests.
- Dedicated Redis authority key factories, strict versioned control/subject-guard codecs, checked Lua scripts for replay, subject block, fenced CLOSED generation installation and control close. Unknown state, wrong type, connection failure and uncertain script reply do not grant authority.

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

The public one-shot password API, durable post-Keycloak outcome/reconciliation, current Customer/guard application, Redis session admission/activation/rotation/logout, guarded exact-envelope recovery and full App→BFF→Auth→Keycloak integration tests **are not implemented**. The new admission service and existing Direct Grant/envelope adapters are not yet wired into a successful login use case. No ACTIVE token is issued. No test here proves G2 is complete or meets the two-second Customer revocation requirement. Keep production admission closed and do not deploy this artifact as a replacement service. Password no longer requires a custom Keycloak SPI; biometric still does.

## Build and test

On the current Mac, the verified command is:

```bash
cd /Users/phuc/BigMoves/mobile-banking/authentication-service
JAVA_HOME=/Users/phuc/Library/Java/JavaVirtualMachines/openjdk-25.0.2/Contents/Home \
./mvnw verify
```

Tests use ephemeral, separate Testcontainers MySQL 8.4, Redis 7.4 and Keycloak 26.7.1 instances. They do not use H2 or the running database/Redis/Keycloak. `./mvnw test` runs unit/architecture/vector tests only; `verify` additionally runs the isolated integration tests. Synthetic vectors are read from `../docs/DD/target/reference/crypto-vectors.json`, `software-key-vectors.json` and `password-one-shot-vectors.json`; older password-JWE cases are historical, not current password acceptance tests.

## Required runtime configuration

`application.yaml` requires explicit MySQL, Redis, server mTLS, workload mTLS, public external origin, BFF workload URI allowlist, bank authority scope, pinned biometric Keycloak context signer, pinned KC ID-token signer, Auth receipt signing key, Customer origin/timeout and Keycloak Direct Grant client identity/timeout. There is no JVM-default-trust fallback. The production Redis preflight requires a single primary with `noeviction` and an explicitly configured positive memory budget. It does not authorize READY; the fenced recovery/rebuild protocol is still required.

The dedicated Redis identity must be permitted to read `INFO server/replication/cluster` and `CONFIG GET maxmemory/maxmemory-policy`, and to execute only the reviewed authority scripts and their required key commands. Missing permissions close startup/admission; no permissive ACL fallback is configured.

Names of mandatory environment inputs are in `src/main/resources/application.yaml`. Do not use test keys, test certificates, or test profile overrides in deployment.

## G1 verification boundary

| Area | Evidence available | Not yet proven by G1 |
|---|---|---|
| Build and architecture | Maven `verify`; ArchUnit positive and negative fixtures | Dependency policy for future controllers/use cases must be enforced as they are added |
| HTTP and TLS | Strict JSON, safe error and URI tests; exact URI-SAN filter tests; local TLS 1.3 client-certificate handshake | Full BFF→Auth deployment trust chain and real partner TLS interoperability |
| Crypto | Shared DPoP, context, enrollment, token-envelope JWE and signing-input vectors | Keycloak/MFA verifier interoperability, App receipt/decryption interop and software-key extraction threat acceptance |
| MySQL | Flyway on fresh MySQL 8.4; constraints, concurrent CAS, mandatory transaction and rollback | Cross-system operation/recovery transactions from G2/G3 |
| Redis | Real Redis replay across adapters, lost reply, wrong type, closed generation, monotonic subject block, key/value schema and preflight | AOF restore/real primary promotion, READY rehydration and session admission from G2/G5 |

Open decisions remain in `../docs/DD/target/17-implementation-readiness.md`: Customer event broker and outage policy under the 2-second block bound, operational nonce/lease timing, retention/privacy, password abuse controls and real Customer/MFA provider agreement. No permissive production defaults were chosen here.
