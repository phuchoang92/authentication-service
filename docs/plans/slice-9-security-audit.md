# Slice 9 — asynchronous security activity audit (`SECURITY_AUDIT_EVENT`)

Status: **implemented 2026-10-31 (turns 1–3)** — table, entity and synchronous batch writer (turn 1); port, login events
and wiring (turn 2); background writer, `auth.audit.*` settings, boot test and docs (turn 3). Nothing committed yet.
(Numbered 9 because the session-actions work committed on 2026-10-31 took slice 8.)

The service kept no history of login attempts: failures only move lockout counters, sessions live in Valkey, and
`TRUSTED_DEVICE_AUDIT` records device-trust transitions in the same transaction as the change (DD 19 §4). This slice
adds a second audit table for **activity**, written on a background thread so login never waits on the SQL insert
(the insert may land before or after the HTTP response is flushed).

## Decisions (2026-10-30 / 2026-10-31)

| Topic | Decision |
|---|---|
| Two tables, by write guarantee | `TRUSTED_DEVICE_AUDIT` = transitions: same transaction, rollback on failure, rare, long retention. `SECURITY_AUDIT_EVENT` = activity: asynchronous, best-effort, high volume, short retention later. One table would carry mixed guarantees and break `UQ_TDA_OPERATION_SEQUENCE`. Both share the vocabulary (event type, reason, customer, channel, time); a `UNION ALL` view can give one customer timeline later. |
| Events in this slice | Login outcomes only: `LOGIN_SUCCEEDED` (FULL_SESSION / RESTRICTED_SESSION), `LOGIN_FAILED` (UNKNOWN_USER / WRONG_PASSWORD), `LOGIN_REFUSED` (LOCKED / CAPTCHA_REQUIRED / NOT_READY), `LOGIN_UNAVAILABLE` (REPOSITORY / PARTNER). Lockout, session and enrollment activity are later slices on the same table. |
| Async model | In-process bounded queue + one virtual-thread writer that batch-inserts in its own transaction. No `@Async`, no executor beans, no Valkey, no broker (none selected; DD 17). |
| Overload / DB down | Drop and count. The request proceeds; a counter increments; a WARN names the event type and exception type only. |
| What is stored | Identifiers only: internal customer ID (NULL for an unknown user name), channel, platform, session ID, failed count, times. Never the user name, password, raw device ID or token. |
| Retention | Open policy gate (DD 17). `IX_SAE_TIME` is there for a future purge job; no cleanup in this slice. |

## Changes

Turn 1 (this turn):
- DB design: `authentication-service-src/docs/db-phases/phase-audit-security-event.sql` + README rows; copied unchanged
  as `V5__security_audit.sql`.
- `domain.enums.SecurityEventType`; `domain.enums.SecurityEventReason`, where each reason names its event type
  (`reason.type()`), so a service picks the reason and the type follows; the event record rejects a mismatch.
- `application.port.out.model.SecurityAuditEvent` (record, builder, non-null type/reason/channel/time).
- `persistence.entity.SecurityAuditEventEntity`, `persistence.repository.SecurityAuditEventJpaRepository`,
  `persistence.mapper.SecurityAuditPersistenceMapper`, `persistence.adapter.SecurityAuditEventPersistenceAdapter`
  (`writeBatch`: one `TransactionTemplate` transaction per batch; `DataAccessException` → `RepositoryUnavailableException`).
- `SecurityAuditEventPersistenceAdapterIT` (entity validates against V5; a batch of 3 is inserts only — the entity
  implements `Persistable` and is always new, so Spring Data skips the SELECT-before-INSERT).
- 2026-10-31 review of slice 10 (another session): `SecurityAuditEvent` keeps the reason only and derives the event
  type from it (`reason.type()`), so no caller can state a contradictory pair and building the event cannot fail on
  real inputs — the one slice-10 change kept. See [slice-10 note](slice-10-shared-activity-audit.md) for what was
  folded back and why.

Turn 2 (implemented):
- `application.port.out.repository.SecurityAuditStore` — `record(event)`: **never blocks, never throws** (the `Store`
  suffix is the ArchUnit rule for that package).
- `LoginService`: `login` = `decide(command)` → wipe password → `securityAuditStore.record(auditEvent(...))` → answer.
  `decide` returns a private `Decision(result, reason, identity, sessionId)` at each exit; `auditEvent` turns it into one
  row (customer when the user name matched, session on success, lockout count on anything but a success). Outages are
  `REPOSITORY` (DB or session store) or `PARTNER` (Keycloak), with no customer.
- `persistence.adapter.DisabledSecurityAuditStore` (no-op) and `config.AuditConfiguration`, which always provides the
  port — for now the no-op; turn 3 switches on the queued store behind `auth.audit.enabled`.
- `LoginConfiguration` injects the store; `LoginConfigurationTest` imports `AuditConfiguration`.
- `LoginServiceTest` + `RecordingSecurityAuditStore`: one test per mapping row (full / restricted / web, unknown user,
  wrong password with count, the locking failure, LOCKED / CAPTCHA_REQUIRED / NOT_READY, PARTNER / REPOSITORY) and the
  password is already wiped when `record` is called.

Turn 3 (implemented):
- `persistence.common.QueuedBatchWriter<E>` (generic, reusable by any append-only best-effort table) + the one-method
  `BatchWriter<E>`: `ArrayBlockingQueue` + one virtual thread (`SmartLifecycle`): `offer` never blocks, full queue →
  drop + count; the loop `take`s one item, `drainTo` up to `batchSize`, calls `write`; any `RuntimeException` from the
  writer (store down, or a bug) drops that batch, counts it and backs off 500 ms — the thread lives on; `stop`
  interrupts, waits `shutdownDrain`, then writes what is still queued. WARN on the first drop and about every 1 000th,
  with the item's label (event type) and exception type only. `droppedCount()` is the future metric.
- `persistence.adapter.QueuedSecurityAuditStore` is the thin shell: `SecurityAuditStore` + `SmartLifecycle` delegating
  to a `QueuedBatchWriter<SecurityAuditEvent>` named `security-audit-writer` whose writer is
  `SecurityAuditEventPersistenceAdapter::writeBatch`. A second audit table needs only its own entity, mapper,
  persistence adapter and port, and reuses the queue unchanged.
- `AuditProperties` (`auth.audit.enabled` false, `queue-capacity` 10000 [100..1 000 000], `batch-size` 100 [1..1000],
  `shutdown-drain` PT2S [≥ 100 ms]); `AuditConfiguration` builds the queued store (exposed by its concrete type so the
  lifecycle is seen) when on, the no-op when off; `application.yaml` gets the `auth.audit` block.
- Tests: `QueuedBatchWriterTest` (lambda store, `String` items: one batch off the caller's thread; full queue drops and
  the caller returns at once; a rejected batch is dropped and the writer keeps going; a bug in the writer costs the
  batch, not the thread; `stop` drains in batches), `QueuedSecurityAuditStoreTest` (an event reaches the SQL writer
  from `security-audit-writer`; drop count and drain delegate), `AuditConfigurationTest`
  (off → no-op and no thread; on → running writer; capacity 10 → startup fails naming `queueCapacity`),
  `ApplicationBootIT` with the audit on: the first four login attempts show up as WRONG_PASSWORD(1), WRONG_PASSWORD(2),
  CAPTCHA_REQUIRED(2), FULL_SESSION with the session ID of the issued token.
- Docs: README (status, gaps, `AUTH_AUDIT_ENABLED`), ARCHITECTURE §7 row 14 "fire-and-forget audit port".

## Trace for a newcomer

`LoginService.login` → `SecurityAuditStore.record` → `QueuedSecurityAuditStore` (queue + thread) →
`SecurityAuditEventPersistenceAdapter.writeBatch` (SQL). Four hops, one file each.
