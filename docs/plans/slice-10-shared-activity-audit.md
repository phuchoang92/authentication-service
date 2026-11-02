# Slice 10 — shared activity audit (reviewed and folded back, 2026-10-31)

Status: **not in the code.** Implemented by a second session on 2026-10-31 on top of [slice 9](slice-9-security-audit.md),
reviewed the same day, and folded back by decision of the owner. This note keeps the reasons so the idea is not re-proposed
without them.

## What it proposed

`AuditService.record(RecordAuditCommand)` with a `domain.model.AuditContext` and a sealed `AuditDetails` payload
(`LoginAuditDetails`, `DeviceTrustedAuditDetails`); a `DEVICE_TRUSTED` event with three reasons emitted from
`TrustedDeviceService` after each trust transaction; `V6__audit_event_details.sql` adding `CORRELATION_ID`,
`SCHEMA_VERSION` and a `DETAILS` JSON column written with Jackson from an allowlist.

## Why it was folded back

1. **It duplicated device-trust facts into the best-effort table.** `TRUSTED_DEVICE_AUDIT` already records trust in the
   same transaction as the change. A second, droppable copy in `SECURITY_AUDIT_EVENT` lets a reader conclude a device was
   never trusted when it was. The two-tables-by-guarantee decision (slice 9) stands: the activity table never holds a fact
   whose authoritative record is elsewhere.
2. **Two hops that did nothing yet.** `RecordAuditCommand(context, details)` and `SecurityAuditEvent(eventId, context,
   details)` differ by one field; `AuditService` only minted it. The stable ID was meant for retries, but the queue drops a
   rejected batch and never retries.
3. **JSON duplicated the columns.** Login rows stored the session ID three times (column, JSON, correlation); trust IDs
   lived only in JSON and could not be indexed. Typed nullable columns are the table's style (DD 19).
4. **Audit value objects in the domain.** Correlation IDs and audit payloads are application concerns; they belong in
   `application.port.out.model`.
5. **Validation on the request path.** The new constructors threw `IllegalArgumentException` outside the login's guard,
   narrowing the "never throws" promise to the store alone.

## What was kept

The event type is derived from the reason (`SecurityAuditEvent.eventType()` = `reason.type()`), so a contradictory
pair cannot be built and construction cannot fail on real inputs. The slice-9 doc wording about insert timing was
corrected: the row may land before or after the HTTP response is flushed.

## If device activity is wanted later

Add a *reason* for an activity that is not a transition (for example a login on an already trusted device) to
`SecurityEventReason`, and call `SecurityAuditStore.record` where the service knows the facts. Do not copy transitions.
