# Slice 4 — trusted device (DB phase 3)

Status: **implemented 2026-10-25** (turns 1–3; see README for the test run). Schema: `phase-3-trusted-device.sql`
(`TRUSTED_DEVICE`, `PRIMARY_TRUSTED_DEVICE`, `TRUSTED_DEVICE_AUDIT`). Unlocks NEED_TRUSTED_DEVICE
routing, the device list and direct primary assignment. Enrollment (init → verify → confirm with
FACE, DD 20 §4) is phase 4; revoke is phase 7.

## Decisions (2026-10-25)

| Topic | Decision |
|---|---|
| Check order (DD 20 §2, settled) | Keycloak password → device trusted? → device primary? |
| First device | No live trusted device for customer + channel → the device of the first successful password login becomes `TRUSTED` and primary **directly**, no MFA (the only trust path in phase 3) |
| Any later device, or trusted-but-not-primary, or expired | `NEED_TRUSTED_DEVICE` with a **restricted session** |
| Restricted session | Valkey, `status=NEED_TRUSTED_DEVICE`, TTL 10 min, no absolute limit, same token/envelope shape; the session filter admits it only on trusted-device routes (none exist yet in this slice) plus logout; extend refuses it (`410`) |
| Login request | `deviceId` required when `channel=MOBILE`, `platform` `ANDROID`/`IOS` required with it, optional `devicePublicKey` (P-256 JWK) stored on the row for phase 5; no possession proof yet |
| WEB channel | no device trust: WEB logins stay `ACTIVE` as today (trusted devices are an app concept) |
| Trust expiry | `EXPIRES_AT = trustedAt + 180 days` (configurable); expired → `NEED_TRUSTED_DEVICE` |
| Device cap | max 5 live devices per customer + channel; trusting a new one (phase 4) will expire the oldest by `LAST_SUCCESSFUL_LOGIN_AT`; in phase 3 only the first device is ever trusted, so the cap is enforced in code but cannot trigger |
| Primary | changes only via phase 4's confirm; a login on the primary updates `LAST_SUCCESSFUL_LOGIN_AT` only |
| Device list | `GET /api/v1/devices` (session-checked, ACTIVE session only): `[{deviceId (decrypted, masked to last 4), platform, status, trustLevel, primary, trustedAt, expiresAt, lastLoginAt}]` |

Proposed value lists (code enums; the DB is keys-only): `STATUS` PENDING/ACTIVE/SUSPENDED/EXPIRED/REVOKED
(`LIVE_SLOT` = PENDING, ACTIVE, SUSPENDED); `TRUST_LEVEL` NONE/TRUSTED; `PLATFORM` ANDROID/IOS;
audit `EVENT_TYPE` DEVICE_REGISTERED, DEVICE_TRUSTED, PRIMARY_ASSIGNED, DEVICE_EXPIRED, DEVICE_LOGIN;
`CAUSE` LOGIN/POLICY; `ACTOR_TYPE` CUSTOMER/SYSTEM; `REASON_CODE` FIRST_DEVICE, PRIMARY_LOGIN,
TRUST_EXPIRED, DEVICE_CAP; `POLICY_VERSION` `td-p3-v1`.

Deviations from DD 19/20 deferred: Kdev possession proof, BFF ES256 JWT on the trusted-device routes,
QR pairing, biometric credentials, revoke/security versions, Redis device guards.

## Keys (config, both ≥ 32 bytes, with key IDs)

- `auth.device.lookup-hmac-keys-base64.{id}` + `auth.device.lookup-key-id` → `CLIENT_DEVICE_ID_LOOKUP` = HMAC-SHA256(key, customerId ‖ channel ‖ deviceId), `…_LOOKUP_KEY_ID`.
- `auth.device.encryption-keys-base64.{id}` + `auth.device.encryption-key-id` → AES-256-GCM, AAD = customerId ‖ channel, ciphertext = version ‖ nonce ‖ ct ‖ tag, `…_KEY_ID`. Decrypt only for the device list.

## Code (role packages)

- `domain.model`: `TrustedDevice` (aggregate: id, customerId, channel, deviceId, platform, status, trustLevel,
  trustedAt, expiresAt, lastLoginAt, publicKey?, version; `isTrusted(now)`, `recordLogin(now)`, `expire()`),
  `DevicePlatform`, `DeviceStatus`, `TrustLevel`, `DevicePolicy` (trustDuration, maxLiveDevices, restrictedTtl),
  `SessionStatus` gains `NEED_TRUSTED_DEVICE`; `Session.startRestricted(...)`.
- `application.port.in`: `LoginResult.Authenticated` gains `status` already (ACTIVE | NEED_TRUSTED_DEVICE);
  `ListDevicesUseCase` → `DeviceSummary` list.
- `application.port.out`: `TrustedDeviceRepository` (`findLive(customerId, channel, deviceId)`, `findLive(customerId, channel)`,
  `trustFirstDevice(TrustedDevice, correlationId)` = device row + primary row + audit in one transaction,
  `recordLogin(device)` CAS, `expire(device)`), `DeviceIdCodec` port? — no: HMAC/AEAD live in the persistence
  adapter (`DeviceIdProtection`), the domain sees `DeviceId` only.
- `application.service`: `TrustedDeviceService` (owns device rules; called by `LoginService` per §6.1:
  `routeAfterPassword(customerId, channel, deviceId, platform, key, now) → Trusted(primary) | FirstDevice | NeedTrust`),
  `DeviceListService`; `LoginService` issues ACTIVE or restricted accordingly; `SessionService.extend` refuses restricted.
- `adapter.out.persistence`: `TrustedDeviceEntity`, `PrimaryTrustedDeviceEntity`, `TrustedDeviceAuditEntity`,
  repositories, `TrustedDevicePersistenceMapper`, `TrustedDevicePersistenceAdapter` (`@Transactional` on
  `trustFirstDevice`), `DeviceIdProtection` (HMAC + AES-GCM with key IDs). `V3__trusted_device.sql` = phase file.
- `adapter.in.web`: `LoginRequest` gains `platform`, `devicePublicKey`; `DeviceController` `GET /api/v1/devices`;
  `SessionFilter` lets `NEED_TRUSTED_DEVICE` sessions reach only `/api/v1/logout` (and later `/api/v1/trusted-device/**`),
  else `403 DEVICE_TRUST_REQUIRED`; codes `DEVICE_TRUST_REQUIRED` vi/en.
- `config`: `DeviceProperties`, `DeviceConfiguration`; `LoginConfiguration` wires `TrustedDeviceService` into `LoginService`
  by concrete type (§12); ArchUnit: service cycle rule already covers Login → TrustedDevice.
- Tests: `TrustedDeviceTest`, `TrustedDeviceServiceTest`, `LoginServiceTest` routing cases, `DeviceIdProtectionTest`
  (vectors, AAD binding, wrong key), persistence IT (live-slot unique, first-device transaction, audit sequence),
  `@WebMvcTest` (restricted filter, device list), boot IT: first device ACTIVE → second device NEED_TRUSTED_DEVICE
  (restricted token cannot extend; can logout) → device list shows one trusted primary.

## Turns

1. Domain + application (TrustedDevice, policy, ports, TrustedDeviceService, LoginService routing, restricted
   Session) + codes; unit tests.
2. Persistence: V3, entities, `DeviceIdProtection`, adapter, IT; `DeviceConfiguration`.
3. Web: login request fields, restricted-session filter rule, device list endpoint, boot IT, README/ARCHITECTURE.
