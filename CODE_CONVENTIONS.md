# Authentication Service v2 — Code conventions

Status: **approved coding conventions, 2026-10-25**. Applies to new and changed v2 Java
code. This document adds conventions and examples, not a source refactor or evidence of
formatter, architecture-test or runtime-test enforcement.

[ARCHITECTURE.md](ARCHITECTURE.md) owns packages, dependency direction, constructors,
Lombok, enums, constants and configuration boundaries. This file owns variable naming,
the presentation of executable business steps, and identifier representation at API boundaries. Shared
[Auth conventions](../docs/authentication-documentation/docs/design-v1/code-conventions.md)
still apply subject to the user-approved v2 architecture overrides; older package and
interface examples do not override v2 decisions. API/security/data contracts are unchanged.

## 1. Write for the reader

- Optimize for a reviewer reading the business flow from top to bottom. Fewer lines are
  not an acceptance criterion. Do not compress expressions to meet a method/class size target.
- Give each meaningful business step its own statement. Make state transitions, external
  calls, persistence operations and their results visible in execution order.
- Introduce a local variable when its name explains a decision, an intermediate state,
  or the boundary between preparation and an effect. Do not create aliases for every
  getter or trivial field copy when they add no meaning.
- Separate logical stages with blank lines. Use braces for conditionals and loops;
  do not put several statements on one line or use nested ternaries for business decisions.
- Extract a method/class only for a cohesive responsibility or independently meaningful
  operation. Do not hide the sequence behind forwarding helpers or generic workflow code.

## 2. Name dependencies by their role

Injected fields and wiring parameters must distinguish a service, repository, policy,
mapper or generator from the data it operates on. Prefer the concrete role in the name:

| Type | Dependency name | Avoid for that dependency |
|---|---|---|
| `TrustedDeviceRepository` | `trustedDeviceRepository` | `devices` |
| `TrustedDeviceJpaRepository` | `trustedDeviceJpaRepository` | `devices` |
| `TrustedDeviceService` | `trustedDeviceService` | `trustedDevices` |
| `TrustedDeviceAuditJpaRepository` | `trustedDeviceAuditJpaRepository` | `audit` |
| `DevicePolicy` | `devicePolicy` | `policy` |
| `RegistrationRestMapper` | `registrationRestMapper` | `mapper` |
| `Supplier<TrustedDeviceId>` | `trustedDeviceIdGenerator` | `deviceIds` |
| `Clock` | `clock` | unnecessary expanded names |

Collection names describe their contents: `liveTrustedDevices`, `devicesExpiredByCap`.
Local object names describe their business meaning or state: `expiredReplacedDevice`,
`completedEnrollment`, `trustConfirmation`, `replacementAudit`. Names such as `d`, `r`,
`tmp`, `data` or `result` are inappropriate when they conceal the business meaning in a
nontrivial expression. Short names remain reasonable for tiny, obvious local scopes.

Use explicit imports. Prefer explicit types for business/security values and outcomes
when `var` would require the reader to inspect another method to identify the type.
Comments explain business reasons and invariants; they do not compensate for obscure names.

## 3. Keep builders readable

- In a multi-field builder, put each field assignment on its own line and `.build()` on
  its own line. Do not chain several field assignments on one line to save vertical space.
- Compute domain transitions or nontrivial decisions before supplying builder fields.
  Builders assemble data; they should not hide the execution of business steps.
- Build a nontrivial request/confirmation into a named local before calling a repository
  or partner. Simple pure value construction can remain inline where it is immediately clear.
- Follow the existing constructor/Lombok rules in architecture §10. A builder is not a
  way to conceal unrelated inputs or construct a dependency bag.

For example, replace this compressed presentation:

```java
return devices.trustConfirmed(TrustConfirmation.builder().device(trusted)
        .replaced(replaced.map(TrustedDevice::expire).orElse(null)).expiredByCap(expired)
        .enrollment(enrollment.complete()).receiptDigest(receiptDigest).build(), correlationId);
```

with explicit stages and meaningful names:

```java
TrustedDevice expiredReplacedDevice = replacedDevice
        .map(TrustedDevice::expire)
        .orElse(null);

DeviceEnrollment completedEnrollment = enrollment.complete();

TrustConfirmation trustConfirmation = TrustConfirmation.builder()
        .device(newTrustedDevice)
        .replaced(expiredReplacedDevice)
        .expiredByCap(devicesExpiredByCap)
        .enrollment(completedEnrollment)
        .receiptDigest(receiptDigest)
        .build();

return trustedDeviceRepository.trustConfirmed(
        trustConfirmation,
        correlationId);
```

These are method fragments: surrounding locals are named consistently with their roles.
The existing nullable replaced-device contract is preserved. This example does not change
which devices expire or when enrollment completes.

## 4. Separate effects from argument construction

- Do not nest a database/HTTP call inside a mapper, builder, another dependency call or
  return-value wrapper. Name the prepared input, perform the effect, then map its result.
- Do not hide `++`, `--`, assignment, or a domain state transition inside argument lists.
  Keep counter advancement and state changes visible as separate statements.
- When an existing call has several positional arguments, especially same-typed strings,
  IDs, booleans or nullable values, format one argument per line and expose their meaning.
  Use scoped constants for fixed codes, meaningful locals for derived values, or an existing
  cohesive input type. Review the API if its signature remains ambiguous; do not invent a
  generic context bag or new wrapper solely to relocate a long argument list.

For the replacement-audit example, existing fixed values can have private names in the
owning class (shared constants follow architecture §11.1):

```java
private static final String AUDIT_CAUSE_LOGIN = "LOGIN";
private static final String AUDIT_REASON_REINSTALL = "REINSTALL";
```

Then the call site can show preparation, sequence advancement, mapping and persistence:

```java
TrustedDevice replacedDevice = confirmation.replaced();
int replacementEventSequence = sequence;
sequence++;

// This existing audit overload accepts absent optional metadata.
String metadataJson = null;

TrustedDeviceAuditEntity replacementAudit = TrustedDevicePersistenceMapper.toAudit(
        replacedDevice,
        correlationId,
        replacementEventSequence,
        EVENT_REPLACED,
        AUDIT_CAUSE_LOGIN,
        AUDIT_REASON_REINSTALL,
        now,
        enrollmentId,
        metadataJson);

trustedDeviceAuditJpaRepository.save(replacementAudit);
```

This fragment belongs after the existing replaced-device guard/expiration step. Keep the
original ordering and increment timing; do not move it after persistence as an incidental
style edit. Do not introduce `null` or a boolean to select an undocumented business path.

For pure filtering/mapping, streams and Optional operations are fine when the intent is
clear. Prefer a loop or named predicate when nested lambdas, ternaries or chained lookups
make a business decision difficult to follow. Avoid persistence/partner effects inside
stream mapping or predicates.

## 5. Identifiers at API boundaries

Application-facing REST IDs are opaque strings. Clients store them and echo them unchanged;
they do not generate server-issued IDs or interpret their internal representation.

| Boundary | Representation | Example |
|---|---|---|
| REST request/response and ID path/query parameters | `String`, unless an explicit protocol contract requires another format | `requestId`, `enrollmentId`, `captchaId` |
| Application/domain | validated, meaningful ID types | `RegistrationId`, `EnrollmentId`, `CaptchaId` |
| Persistence | the approved internal key representation | UUID / MySQL `BINARY(16)` where already selected |

- REST DTOs use `String` for these fields, not `java.util.UUID`. API schemas describe them
  as strings without `format: uuid` unless UUID formatting is an explicit contract. Typed
  IDs remain in application/domain signatures; this is not a move to strings everywhere.
- REST mappers or focused codecs convert between the public string and the typed ID.
  Decode and validate according to the existing identifier contract, keeping malformed-input
  handling at the REST boundary. `String` does not mean arbitrary unchecked input. Do not
  trim, lowercase, reformat or otherwise normalize an opaque ID without a defined contract.
- Internal decoding may still use UUID parsing for an ID issued in that representation.
  UUID is an implementation detail of that ID codec, not something clients must parse.
  Provider-specific request/response formats remain owned by their adapter contracts.
- UUID already serializes as a JSON string. Changing a DTO field from UUID to `String`
  alone need not change its wire value or remove its UUID appearance. Preserve currently
  issued strings; a different encoding, generator or public ID scheme is a separate contract
  decision, not an incidental naming/formatting edit.
- Internal UUID keys and `BINARY(16)` storage remain valid. This rule does not authorize
  schema migrations or exposing IDs that are currently private, such as internal session IDs.
- Explicitly UUID-based protocol fields, including a selected signed `Idempotency-Key`
  contract, retain their exact validation and signing rules. They are exceptions to the
  default opaque server-issued-ID convention, not a reason to type every REST ID as UUID.

For example, the REST response declares a string:

```java
public record RegistrationResponse(
        String requestId,
        String customerId,
        String userName,
        String state) {
}
```

For a `RegistrationId` currently backed by UUID, its REST mapper can preserve the current
UUID text while returning a string-typed field:

```java
String publicRequestId = ready.requestId().value().toString();

RegistrationResponse registrationResponse = new RegistrationResponse(
        publicRequestId,
        ready.customerId().value(),
        ready.userName().value(),
        "READY");
```

Here `.value().toString()` explicitly encodes the internal UUID. Do not use an arbitrary
domain object's `toString()` as an ID codec. Before accepting source changes, verify JSON
round trips, malformed-input mapping, unchanged existing values and the generated API schema;
no such implementation changes or runtime checks are performed by this document update.

## 6. Keep review and behavior separate

- Readability edits preserve evaluation order, exception propagation, optional values,
  transaction boundaries, affected-row checks, audit ordering and external code literals.
  Do not treat better formatting as proof of concurrency or recovery correctness.
- Do not add behavior, retries, configuration defaults or new abstractions as part of a
  naming/formatting change. Changes to a contract require their own explicit decision.
- Review names and business sequencing manually. A formatter can arrange whitespace;
  it cannot decide whether `devices` is a repository or whether a transition is hidden.
- Check changed production code with the applicable build/static/behavior checks. This
  documentation-only update runs none of those checks and does not claim the existing
  source already follows these conventions.

Before accepting new or changed code, a reviewer should be able to answer:

1. Can I distinguish dependencies from collections by their names?
2. Can I see each meaningful business step and state transition in order?
3. Are builders readable without expanding several operations on the same line?
4. Are I/O, mapping, and counter changes visible rather than nested in arguments?
5. Do locals/abstractions clarify meaning without just moving complexity elsewhere?
6. Are existing behavior and the actual verification results reported separately?
7. Are public IDs opaque strings, core IDs typed, and any UUID-specific protocol exceptions explicit?
