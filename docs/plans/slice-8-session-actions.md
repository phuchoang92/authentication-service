# Slice 8 — common session actions, one Valkey read per request, plain delete

Status: **approved 2026-10-27, in progress** (turn 1: common `SessionService`, `SessionManagementService`, `SessionStore.delete`).

## Context

- `LoginService`, `DeviceEnrollmentService` and `DeviceApprovalService` each repeated "find the live restricted session",
  "consume it, start an ACTIVE one, generate the token, seal the envelope, store it" and "write the terminal state, then
  delete the session" on the raw `SessionStore` port; `SessionService` implemented use cases directly on the same port.
  The rule already applied to devices (`TrustedDeviceService` = common actions, flows above compose them) now applies to
  sessions.
- `SessionFilter` resolved the session on every `/api/**` request and the use case read it again. With the BFF also
  reading the HASH to admit the request that was three reads; the filter read is the redundant one (turn 2).
- `deleteIfCurrent` cost WATCH + HGETALL + MULTI/DEL/EXEC after the caller had already read the session. One atomic `DEL`
  gives both things the callers need: "remove it" and "exactly one of two racing callers wins".

## Decisions (2026-10-27)

| Topic | Decision |
|---|---|
| `SessionService` | common actions only, no use-case interface: `findLive`, `findRestricted`, `findActive`, `newSessionId`, `issueActive`, `issueRestricted`, `saveIfCurrent`, `extend` (bounded CAS retry), `consume`, `end` |
| `SessionManagementService` | implements `CurrentSessionUseCase`, `ExtendSessionUseCase`, `LogoutUseCase` on top of `SessionService` |
| Flows | `LoginService`, `DeviceEnrollmentService`, `DeviceApprovalService` call `SessionService`; they no longer hold the sealer, the token generator, the session-ID generator or the session policy |
| `SessionStore.delete(lookup)` | one `DEL`, true when this call removed the key; replaces `deleteIfCurrent`; `saveIfCurrent` keeps its WATCH/MULTI/EXEC |
| Logout | idempotent: a live session is ended, a missing one is already ended; a logout racing another write succeeds (was 503) |
| Filter (turn 2) | validates the Bearer token format only and passes it through; each use case performs the single Valkey read it needs and answers `DEVICE_TRUST_REQUIRED` / `SESSION_REQUIRED` itself |
| `DeviceManagementService` (turn 2) | implements `ListDevicesUseCase` (and later revoke / rename / history); `TrustedDeviceService` keeps only common device actions |
| BFF-forwarded identity | later, tied to BFF authentication; not in this slice |

## Turns

1. `SessionService` common actions, `SessionManagementService`, `SessionStore.delete`, flows and wiring, tests; `mvn -o verify`.
2. Filter stops resolving, `ListDevicesCommand` / `ListDevicesResult`, `DeviceManagementService`, docs; `mvn -o clean verify`.
