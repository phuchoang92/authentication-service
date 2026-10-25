# Authentication Service v2 — Codebase Architecture

Status: **target design, approved 2026-10-25**. The code is being moved onto it slice by
slice; "current" notes below say where the code still differs. **[arch]** marks rules intended
for `ArchitectureTest`; it is not proof that a rule is already enforced. Direct service
calls between services and role-based domain/application/rest/persistence packages are
documentation targets in this update; no source or architecture tests are changed.
The separate `application.command` / `application.result` packages, role-based subpackages
under `application.port.out`, the `rest` naming, and the common `infrastructure` parent for
adapters/config form the selected layout. Current notes (§3) distinguish recorded
implementation status from newly approved documentation targets.
Business enums in `domain.enums` and adapter-owned `constant` packages (§11.1) are also
documentation targets; this update does not move enum/constant source files or tests.

This phase builds the business flow bottom-up. It adds no CAS, concurrency or performance
design; the existing registration, persistence and security contracts remain unchanged.

[CODE_CONVENTIONS.md](CODE_CONVENTIONS.md) defines dependency/local naming and readable
business-step presentation. Package structure belongs here; those code-writing rules apply
to new and changed source. Read it before changing v2 Java code. This documentation update
does not refactor existing production code.

---

## 1. Goals

1. A newcomer can trace one request from HTTP to SQL by opening files top to bottom, without
   knowing Spring internals.
2. Business rules live in plain Java that runs in a unit test with no container.
3. Every technology (Spring MVC, JPA, RestClient, Keycloak, Valkey) sits behind an interface
   and can be replaced or stubbed in isolation.
4. The same shape repeats for every capability, so the second capability costs less than
   the first and review is about rules, not structure.
5. No overcoding: a package, interface or mapper exists only when a rule in this document
   requires it.

---

## 2. Style: Hexagonal (Ports & Adapters), layer-first

The code is split into four **rings**. Dependencies between rings point inward;
`infrastructure.config` assembles them. Services within the application ring may call each
other as described in §6.1. `infrastructure` groups adapters and configuration; it is not
an extra ring or an extra runtime step. Domain and application must never import it.

```text
            ┌────────────────── infrastructure.adapter.in ───────────────────────┐
            │  HTTP in: controllers, request/response DTOs, REST mappers          │
            │   ┌────────────────────────── application ──────────────────────┐  │
            │   │  port.in, command/result, port.out, services                │  │
            │   │   ┌──────────────────────── domain ───────────────────────┐  │  │
            │   │   │  aggregates, value objects, enums, domain exceptions  │  │  │
            │   │   └───────────────────────────────────────────────────────┘  │  │
            │   └─────────────────────────────────────────────────────────────┘  │
            └───────────────────────────────────────────────────────────────────┘
            ┌────────────────── infrastructure.adapter.out ──────────────────────┐
            │  JPA entities + repositories, HTTP partner clients, their DTOs     │
            └───────────────────────────────────────────────────────────────────┘
            ┌──────────────────── infrastructure.config ────────────────────────┐
            │  Spring wiring; sees everything, contains no logic                 │
            └───────────────────────────────────────────────────────────────────┘
```

Direction of dependencies:

```text
infrastructure.adapter.in  ──► application.port.in  ──► domain
            + application.command / application.result
application.service.LoginService ──► application.service.TrustedDeviceService
                                  + published application.command/application.result values
infrastructure.adapter.out ──► application.port.out ──► domain
infrastructure.config      ──► all rings (creates beans)
```

**Layer-first throughout** means domain, application, REST and persistence are grouped by
role, without business subpackages such as `registration`, `login`, `session` or
`trusteddevice`. Business ownership is expressed by class names and responsibilities,
not folders: `Registration`, `LoginService`, `TrustedDeviceService`, and their contracts.
Domain aggregates and value objects, including values used by several flows, live in
`domain.model`; business enums live in `domain.enums`. No separate `domain.shared` package
is needed. Fixed literals stay with their owning class or adapter (§11.1), not in a
service-wide constants package.
Partner adapters remain grouped by external system (`customer`, `keycloak`, `notification`).

---

## 3. Package layout

```text
com.vpbank.dcp.auth
├── AuthenticationApplication                 @SpringBootApplication, nothing else
│
├── domain                                    ring 1 — pure Java
│   ├── model                                 Registration (aggregate), RegistrationId, RequestDigest,
│   │                                         CustomerId, UserName, PhoneNumber, Email
│   ├── enums                                 RegistrationState, DeviceStatus, DevicePlatform, TrustLevel
│   └── exception                             RegistrationStateException
│
├── application                               ring 2 — pure Java, orchestrates the domain
│   ├── command                               RegisterCustomerCommand
│   ├── result                                RegisterCustomerResult
│   ├── port
│   │   ├── in                                RegisterCustomerUseCase (interfaces only)
│   │   └── out
│   │       ├── repository                    RegistrationRepository, CustomerAuthenticationRepository,
│   │       │                                 SessionStore, CaptchaStore
│   │       ├── gateway                       CustomerDirectoryPort, IdentityProviderPort, SmsSenderPort,
│   │       │                                 CredentialVerifierPort, TokenEnvelopeSealer,
│   │       │                                 OpaqueTokenGenerator, CaptchaGenerator
│   │       ├── model                         NewIdentityUser, InitialPasswordSms, CustomerProfile,
│   │       │                                 CustomerAuthentication, StoredSession
│   │       └── exception                     RepositoryUnavailableException, PartnerUnavailableException,
│   │                                         InvalidEncryptionKeyException
│   └── service                               RegisterCustomerService (implements the use case),
│                                             RequestDigester, InitialPasswordGenerator
│                                             Other flows: LoginService, TrustedDeviceService
│
└── infrastructure                           technical implementation + composition root
    ├── adapter
    │   ├── in
    │   │   └── rest                              ring 3 — Spring MVC REST API
    │   │       ├── common                        ApiEnvelope<T>, ApiError, FieldDetail, InvalidRequestException,
    │   │       │                                 GlobalExceptionHandler, ResponseHeadersFilter,
    │   │       │                                 ErrorMessages (localized text by code)
    │   │       ├── constant                      ErrorCodes (shared REST error-code literals)
    │   │       ├── controller                    RegistrationController
    │   │       ├── dto
    │   │       │   ├── request                   RegistrationRequest
    │   │       │   └── response                  RegistrationResponse
    │   │       └── mapper                        RegistrationRestMapper
    │   └── out                                   ring 3 — technology clients
    │       ├── persistence
    │       │   ├── common                        AuditedEntity (@MappedSuperclass)
    │       │   ├── adapter                       RegistrationPersistenceAdapter (implements RegistrationRepository)
    │       │   ├── entity                        RegistrationEntity, CustomerAuthenticationEntity
    │       │   ├── repository                    RegistrationJpaRepository,
    │       │   │                                 CustomerAuthenticationJpaRepository
    │       │   └── mapper                        RegistrationPersistenceMapper
    │       ├── customer
    │       │   ├── CustomerHttpAdapter           implements CustomerDirectoryPort
    │       │   ├── dto                           CustomerProfileDto
    │       │   └── mapper                        CustomerProfileMapper
    │       ├── keycloak
    │       │   ├── KeycloakAdminAdapter          implements IdentityProviderPort
    │       │   ├── constant                      KeycloakEndpoints (when shared; otherwise private constants)
    │       │   ├── dto                           TokenResponse, CreateUserRequest, CredentialRequest,
    │       │   │                                 EnableUserRequest
    │       │   └── mapper                        KeycloakUserMapper
    │       └── notification
    │           ├── NotificationHttpAdapter       implements SmsSenderPort
    │           ├── constant                      shared fixed literals, only when needed
    │           ├── dto                           SmsRequest, SmsResponse
    │           └── mapper                        SmsMapper
    │
    └── config                                    ring 4 — Spring only
          RestConfiguration (LocaleResolver, MessageSource, filters),
          JpaConfiguration, RegistrationConfiguration, RegistrationProperties

src/main/resources
├── messages/errors_vi.properties             error code → Vietnamese text (default language)
├── messages/errors_en.properties             error code → English text
└── ValidationMessages_vi.properties, ValidationMessages_en.properties   Bean Validation texts
```

**Current (2026-10-25, slices 1–4 implemented, slice 5 turns 1–2 implemented, layout and
conventions applied):** the source uses `infrastructure.adapter.in.rest` (`*RestMapper`,
`RestConfiguration`), `infrastructure.adapter.out.*`, `infrastructure.config`,
`application.command` / `application.result`, `application.port.in` with use-case interfaces
only, and `application.port.out.{repository,gateway,model,exception}` with no top-level types at
the root. Business enums live in `domain.enums` (`DomainEnumCodesTest` freezes their names, which
are the stored and wire codes), `ErrorCodes` lives in `infrastructure.adapter.in.rest.constant`,
and the one partner `constant` package so far is `adapter.out.keycloak.constant.KeycloakEndpoints`
(paths shared by three Keycloak classes). Production code follows
[CODE_CONVENTIONS.md](CODE_CONVENTIONS.md): role-named dependencies, one business step per
statement, one builder field per line, effects outside argument lists. `ArchitectureTest`
enforces the preceding splits, the enum and constant homes, the ban on `infrastructure` imports
from domain and application, the controller rule (no `domain` dependency; the REST mapper builds
value objects), the outbound-contract independence rule, the onion rings, service cycles and the
Lombok allow-list. Implemented flows: registration (slice 1), login/session (slice 2), password
lockout with CAPTCHA (slice 3), trusted devices (slice 4: `TrustedDeviceService` called by
`LoginService` — the §6.1 composition is real), enrollment domain/application/out adapters
(slice 5 turns 1–2; the REST routes are turn 3). Slice decisions:
`docs/plans/slice-2-login-session.md`, `slice-3-password-lockout.md`, `slice-4-trusted-device.md`,
`slice-5-enrollment.md`.
That record does not verify the new enum/constant layout. Its implementation slice must
update architecture checks and preserve enum wire/storage codes; no tests are run here.

---

## 4. What each ring contains, and what it may import

| Ring | Package | Contains | May import | Must not import **[arch]** |
|---|---|---|---|---|
| Domain | `domain..` | `model` (aggregates, value objects), `enums` (business states/categories), `exception` | `java..`, `lombok.Builder`, domain types | Spring, Jakarta, `application`, `infrastructure..` |
| Application | `application..` | `command`, `result`, `port.in` (HTTP UseCase interfaces only), `port.out.repository`, `port.out.gateway`, `port.out.model`, `port.out.exception`, `service` (including optional plain-Java settings) | domain types for its own business rules, shared domain values, its own outbound ports and helpers, other services and published `command` / `result` contracts (§6.1), `java..`, `javax.crypto..`, `lombok.Builder`; `lombok.RequiredArgsConstructor` and `lombok.NonNull` for constructor injection (§10) | Spring, Jakarta, `infrastructure..` (including framework properties); bypassing another service's ownership through its repository or internal aggregate |
| Adapter in | `infrastructure.adapter.in..` | controllers, request/response DTOs, REST mappers, envelope, error handler, filters | `application.port.in`, `application.command`, `application.result`, domain values for REST mapping only, Spring MVC, Jakarta Validation | `infrastructure.adapter.out..`, JPA entities, `application..service`; controllers also follow the narrower rule below |
| Adapter out | `infrastructure.adapter.out..` | JPA entities + Spring Data repositories + persistence adapter; HTTP clients + wire DTOs + adapter | `application..port.out`, `domain..`, Spring Data / JPA / RestClient | `infrastructure.adapter.in..`, another `infrastructure.adapter.out.<x>` package, `application..service` |
| Config | `infrastructure.config` | `@Configuration`, `@ConfigurationProperties` | everything | business logic (no `if` on business data) |

Additional **[arch]** rules:

- **Controllers are glue** (convention, reviewed): bind path/headers/body, `toCommand(...)`,
  call the use case, `toResponse(result)`. A controller never decides a business outcome or
  an HTTP status; the result → status/code table is a mapping and lives in `toResponse`.
  Transport-only headers (e.g. `Set-Cookie`) may be added by the controller. Trivial endpoints
  still get a mapper, so the mapping is always in the same place. Mappers are static; one
  becomes a bean only when it needs a dependency.
- **[arch]** A controller depends only on `application.port.in`, `application.command`,
  `application.result`, REST `dto`/`mapper`,
  `infrastructure.adapter.in.rest.common` and Spring MVC — never on `domain..` (including model/enums), `port.out`, `service`
  or entities.
- A class whose name ends in `Request` or `Response` lives in a `dto` package (REST or partner).
- A class whose name ends in `Mapper` lives in a `mapper` package and is `final`; static methods
  unless it needs a dependency such as `ErrorMessages`, then an instance created in config.
- A class whose name ends in `Entity` lives in `infrastructure.adapter.out.persistence..entity`.
- A class whose name ends in `UseCase` lives in `application.port.in`. Storage interfaces
  (`...Repository`, `...Store`) live in `application.port.out.repository`; other adapter
  capability interfaces (`...Port`, generators, crypto capabilities) live in
  `application.port.out.gateway`. Both groups are outbound ports.
- `application.port.in` contains inbound interfaces only. Application operation commands
  and their input values live in `application.command`; operation results and their output
  values live in `application.result`. Genuine shared domain values remain in `domain.model`;
  business states/categories live in `domain.enums`.
  Outbound-only input/output values live in `application.port.out.model`, and dependency
  failure exceptions in `application.port.out.exception`, not in the service command/result
  packages. A small outcome used by only one port may remain nested in that interface.
  The root `application.port.out` has no top-level types. See §5.1 for contract ownership.
- An application service may call another capability's published service class directly,
  using constructor injection and its published command/result contracts (§6.1). No
  cross-capability repository access, internal domain access, or circular service dependencies.
- Domain, application, REST and persistence use role packages only. A capability denotes
  logical business ownership, not a package. Service ownership rules are reviewed at class
  and method level; shared role packages do not enforce those rules by themselves.
- All adapters live under `infrastructure.adapter`; framework wiring/properties live under
  `infrastructure.config`. Core-owned ports stay under `application.port`. No domain or
  application dependency on any `infrastructure` type is allowed.
- Business enums use `domain.enums` (plural; `enum` is a Java keyword). Shared fixed
  non-SQL literals use the owning adapter's `constant` package; single-class literals stay
  private and adjustable values stay in properties. Port outcomes and provider enums follow
  the ownership exceptions in §11.1, not a blanket "all enums in domain" rule.
- Lombok allow-list, see §10.

---

## 5. Type catalogue — where does a new class go?

| You are writing… | It goes to | Shape |
|---|---|---|
| A thing with identity and a lifecycle (registration, session, device) | `domain.model` | immutable `record`, `@Builder(toBuilder = true)`, named transition methods returning a new instance |
| A validated small value (customer ID, phone, PIN length) | `domain.model` | `record` with compact constructor that throws `IllegalArgumentException`; `toString` redacts personal data |
| Business states/categories | `domain.enums` | `enum`, with pure helpers such as `finished()`; no I/O or collaborators |
| A small outcome belonging to one port | nested in that outbound interface | enum or sealed result; does not become a domain enum solely because its set is closed |
| Provider-specific enum | owning `infrastructure.adapter.out.<partner>.dto` or its internal types | provider wire representation; mapped to core values without leaking into domain |
| Fixed literal used by one class | owning class | `private static final`; prefer existing framework/library constants |
| Fixed non-SQL literals shared within an adapter | owning adapter's `constant` package | focused final holder with private constructor, e.g. `ErrorCodes` or `KeycloakEndpoints`; no global constants dump |
| Adjustable lifetime, limit or timeout | `infrastructure.config` properties | validated configuration; never converted to a constant merely to shorten wiring |
| "This step is not allowed from this state" | `domain.exception` | extends `IllegalStateException`; a bug, mapped to 500 |
| Published input to a service operation | `application.command` | `XxxCommand` record and operation-specific input values (`@Builder` if > 4 fields), used by HTTP use cases or direct service callers; no other capability's internal domain types |
| Published output of a service operation | `application.result` | `sealed interface XxxResult` when outcomes differ, plus operation-specific output values; immutable values, not entities or internal aggregates; business failures are outcomes, not exceptions |
| HTTP entry contract | `application.port.in` | `XxxUseCase` interface invoked by a controller; no interface required for every public service method |
| Business operation or cohesive group of operations | `application.service` | `final class XxxService`; implements a UseCase for HTTP entry operations; final dependencies, `@RequiredArgsConstructor` for assignment-only construction or an explicit constructor for initialization logic (§10); no Spring annotations |
| Cohesive application settings, when needed | `application.service` | immutable plain-Java `XxxSettings` record; created from validated properties in config (§12), no Spring/Jakarta annotations or collaborator fields; no wrapper required for one setting |
| Storage capability (database or Redis) | `application.port.out.repository` | technology-neutral interface such as `RegistrationRepository` or `SessionStore`; both are outbound ports |
| Non-storage capability supplied by an adapter | `application.port.out.gateway` | interface such as `IdentityProviderPort`, `TokenEnvelopeSealer` or `CaptchaGenerator`; a gateway need not make an HTTP call |
| Outbound-only input/output data | `application.port.out.model` | immutable application-owned contract such as `NewIdentityUser`, `CustomerProfile` or `StoredSession`; no provider wire DTOs or entities; group parameters only when cohesive |
| Dependency failure to distinguish | `application.port.out.exception` | `RepositoryUnavailableException`, `PartnerUnavailableException`, `InvalidEncryptionKeyException`; no vendor exception types leaked into application |
| HTTP entry point | `infrastructure.adapter.in.rest.controller` | controller invokes an inbound UseCase, never a concrete service |
| HTTP body in | `infrastructure.adapter.in.rest.dto.request` | `record` with Jakarta Validation; strings only; `toString` redacted |
| HTTP body out | `infrastructure.adapter.in.rest.dto.response` | `record`; strings and primitives only |
| Request → command, result → `ResponseEntity` | `infrastructure.adapter.in.rest.mapper` | `final class XxxRestMapper` with `toCommand`, `toResponse`; static unless it needs a dependency (`ErrorMessages`), then created in config |
| Table row | `infrastructure.adapter.out.persistence.entity` | JPA class, see §8 |
| Query | `infrastructure.adapter.out.persistence.repository` | `interface extends JpaRepository`, derived queries, `@Lock` where needed |
| Entity ↔ domain | `infrastructure.adapter.out.persistence.mapper` | `final class XxxPersistenceMapper` static `toEntity`, `toDomain`, `apply(entity, domain)` |
| Port implementation over JPA | `infrastructure.adapter.out.persistence.adapter` | `@Transactional` class; translates Spring exceptions into port exceptions/results |
| Partner JSON | `infrastructure.adapter.out.<partner>.dto` | `record`s named after the partner's payloads; Lombok `@Builder` allowed |
| Partner JSON ↔ port value types | `infrastructure.adapter.out.<partner>.mapper` | `final class` static methods |
| Bean wiring and framework properties | `infrastructure.config` | one `XxxConfiguration` per capability; `XxxProperties` as validated records; maps to plain-Java settings or a scalar before injection into application (§12) |

### 5.1 Service commands versus outbound contract models

These describe different requests at different boundaries, not two copies of one command:

```text
RegisterCustomerCommand                 application.command: perform the registration business operation
  → RegisterCustomerService             application.service: validate and coordinate its steps
      → NewIdentityUser                 application.port.out.model: data for one identity-provider step
      → IdentityProviderPort            application.port.out.gateway: request that dependency capability
      → CreateUserRequest               infrastructure.adapter.out.keycloak.dto: provider HTTP representation
```

- Use `...Command` for inputs to application business operations, whether invoked through
  a UseCase or directly by another service. Keep those types in `application.command`.
- Outbound models describe only the input/output needed for a dependency operation. Prefer
  meaningful names such as `NewIdentityUser` and `InitialPasswordSms`; they are not additional
  application commands. A repository can accept a domain aggregate directly where appropriate.
- The application service builds the outbound input after its business checks; the adapter
  maps that input to its own wire DTO or entity. Outbound interfaces must not depend on
  `application.command`, `application.result`, UseCase interfaces or service implementations.
- Separate a contract when it has a different meaning, lifecycle or external boundary.
  Do not duplicate an entire service command into an identical outbound wrapper solely to
  move data through another package. Reuse suitable domain values without creating aliases.
- Standalone outbound input/output records live in `port.out.model`; a small single-port
  outcome such as `RegistrationRepository.ReserveResult` can stay nested in its interface.
  Normal dependency outcomes remain typed results; dependency exceptions are separate from
  domain invariant exceptions and stay in `port.out.exception`.

---

## 6. One request, top to bottom (registration)

```text
POST /internal/v1/callback/authentication-creation
  │
  ▼ infrastructure.adapter.in.rest.controller.RegistrationController
  │   @Valid RegistrationRequest (dto.request)          ← 400 REQUEST_REJECTED if invalid
  │   RegistrationRestMapper.toCommand(request)          ← builds CustomerId, UserName, PhoneNumber, Email
  ▼ application.port.in.RegisterCustomerUseCase.register(command)
  │
  ▼ application.service.RegisterCustomerService
  │   requestDigester.digest(command)                    RequestDigester (HMAC-SHA256)
  │   registrationRepository.findLatest(customerId)      outbound storage read
  │   customerDirectoryPort.profile(customerId)          outbound partner read
  │   registration = Registration.reserve(...)          domain creation
  │   registrationRepository.reserve(registration)       storage reservation
  │   identityProviderPort.createDisabledUser(newIdentityUser)
  │   userCreatedRegistration = registration.markUserCreated(identityIssuer, identitySubject)
  │   registrationRepository.save(userCreatedRegistration)
  │   identityProviderPort.setPassword(identitySubject, password)
  │   smsSenderPort.sendInitialPassword(initialPasswordSms)
  │   smsAcceptedRegistration = userCreatedRegistration.markSmsAccepted()
  │   registrationRepository.save(smsAcceptedRegistration)
  │   identityProviderPort.enable(identitySubject)
  │   completedRegistration = smsAcceptedRegistration.complete()
  │   registrationRepository.complete(completedRegistration)  identity row + READY, one DB transaction
  │   → RegisterCustomerResult.Ready / IdentityConflict / ProfileIncomplete / Unavailable
  ▼
  infrastructure.adapter.in.rest.mapper.RegistrationRestMapper.toResponse(result)
      Ready(created=true)  → 201 {success:true, data:{requestId, customerId, userName, state:"READY"}}
      Ready(created=false) → 200 same body
      IdentityConflict     → 409 IDENTITY_CONFLICT
      ProfileIncomplete    → 409 CUSTOMER_PROFILE_INCOMPLETE
      Unavailable          → 503 ACCOUNT_CREATION_UNAVAILABLE
```

Reading rule: a reviewer reads **controller → mapper → service → domain → adapter** and never
needs to open `infrastructure.config` to understand behaviour.

### 6.1 Calls between services in the same application

The application service owns the sequence of business steps. It calls domain objects for
rules and transitions, its own outbound ports for technology boundaries, and another
capability's service when it needs that capability's business operations.

Login → Trusted Device as implemented in slice 4 (`LoginService` → `TrustedDeviceService.routeAfterPassword`):

```text
LoginController                         infrastructure.adapter.in.rest.controller
  → LoginUseCase                        application.port.in
  → LoginService                        application.service
      → TrustedDeviceService            application.service
          → TrustedDeviceRepository     application.port.out.repository
          → TrustedDevicePersistenceAdapter  infrastructure.adapter.out.persistence.adapter
          → DB
```

- Inject `TrustedDeviceService` into `LoginService` through its constructor. This is an
  ordinary Java call in the same application; no HTTP hop or forwarding interface is needed.
  Controllers still call inbound UseCase interfaces, not service classes.
- Services share `application.service`; their published inputs live in `application.command`
  and outputs in `application.result`. These packages do not imply shared business ownership.
  Call only the owning service's published entry points, not its helpers. Public signatures use shared
  values or self-contained contract values; they do not expose the capability's internal domain
  aggregate, persistence entities, repository ports or partner payloads.
- Login owns login ordering and the decision about its next step. Trusted Device owns its
  device rules and state changes. The caller must not reproduce those rules by accessing
  the other capability's repository or by chaining low-level setters.
- A service operation may read data, apply domain rules, update state, and return the
  result. Keep reads and writes that form one business action within the owning capability's
  operation. Persistence adapters retain their existing local transaction responsibility.
- One cohesive service may expose several operations. Do not create one UseCase interface
  per method or add `TrustedDeviceCommands`, `TrustedDeviceQueries`, or an interface whose
  only job is forwarding to `TrustedDeviceService`. CQRS is not required in this phase.
- Keep service dependencies acyclic: if Login calls Trusted Device, Trusted Device must
  not call Login back, directly or transitively. Revisit ownership or the caller's sequence
  rather than introducing a callback cycle.

These are target design rules. This documentation update adds neither those capabilities
nor ArchUnit enforcement for their dependency direction. Business ownership remains a
class/method contract even though the classes share role packages.

---

## 7. Patterns and the reason each one exists

| # | Pattern | Why | Where |
|---|---|---|---|
| 1 | Ports & Adapters | technology swap and isolated tests | `port.out` interfaces, `infrastructure.adapter.out` implementations |
| 2 | Inbound UseCase for HTTP entry | the controller depends on an entry contract; internal service calls use classes without an interface per method | `port.in`, `service` |
| 3 | Command / Result objects | no long parameter lists; outcomes are explicit and exhaustive (`switch` on sealed type) | `application.command`, `application.result` |
| 4 | Sealed results, not business exceptions | a conflict is a normal answer, not a stack trace; the compiler checks every case is handled | `application.result`, REST mapper |
| 5 | Rich aggregate | the state machine is in one file with one test; adapters cannot bypass it | `domain.model` |
| 6 | Compare-and-set versioning | two concurrent calls never both advance a row; `@Version` in JPA, the domain carries the expected version | aggregate + persistence adapter |
| 7 | Mapper per adapter | wire/table shapes never leak into domain; each mapping is a table a reviewer can read; static unless it needs a dependency (e.g. `ErrorMessages`) | `mapper` packages |
| 8 | Transaction at the adapter | no SQL transaction spans an HTTP call to a partner; services stay plain classes | `@Transactional` on persistence adapters only |
| 9 | Configuration per capability | the whole object graph of one feature is one file; feature flag in one place | `infrastructure.config.XxxConfiguration` |
| 10 | Envelope + global error handler | one response shape; infrastructure errors mapped once | `infrastructure.adapter.in.rest.common` |
| 11 | Value objects | validate once, carry meaning in signatures (`UserName`, not `String`) | `domain.model` |
| 12 | ArchUnit guard | executable checks guard implemented rules; new targets need explicit test updates before enforcement can be claimed | `ArchitectureTest` |
| 13 | Direct service composition | reuse the owning capability's business operations without a forwarding interface or HTTP call | `application.service` (§6.1) |

Patterns deliberately **not** used: generic `BaseService`/`BaseController`, repository
interfaces in the domain for every entity, MapStruct, `@Service`/`@Component` scanning for
business classes, DTO inheritance, exceptions for flow control, Lombok `@Data`.

---

## 8. Persistence rules (Spring Data JPA on a keys-only schema)

- Flyway owns the schema (`V1__identity.sql` = design phase 1). JPA runs with
  `spring.jpa.hibernate.ddl-auto=validate`, `spring.jpa.open-in-view=false`,
  `hibernate.jdbc.time_zone=UTC`.
- The database has **PK + UNIQUE keys only** (no CHECK, no FK). Rules live in the domain;
  UNIQUE keys stop races and surface as `DataIntegrityViolationException`, which the adapter
  translates into a port result (`UserNameTaken`, `CustomerHasOpen`) or
  `RepositoryUnavailableException`.
- Entity shape:

```java
@Entity @Table(name = "CUSTOMER_AUTHENTICATION_REGISTRATION")
@Getter @Builder @NoArgsConstructor(access = PROTECTED) @AllArgsConstructor(access = PRIVATE)
public class RegistrationEntity extends AuditedEntity {
    @Id @Column(name = "REQUEST_ID", columnDefinition = "BINARY(16)") private UUID requestId;
    @Column(name = "CUSTOMER_ID") private String customerId;
    @Column(name = "USERNAME") private String userName;
    @Enumerated(EnumType.STRING) @Column(name = "STATE") private RegistrationState state;
    @Column(name = "REQUEST_DIGEST", columnDefinition = "BINARY(32)") private byte[] requestDigest;
    @Column(name = "IDENTITY_ISSUER") private String identityIssuer;
    @Column(name = "IDENTITY_SUBJECT") private String identitySubject;
    @Column(name = "EXPIRES_AT") private Instant expiresAt;
    @Column(name = "OPEN_SLOT", insertable = false, updatable = false) private Byte openSlot; // generated TINYINT
    @Version @Column(name = "VERSION") private long version;
}
```

- No setters. The persistence mapper has `apply(entity, domain)` that copies the new state
  from the aggregate; it is the only write path.
- Generated columns (`OPEN_SLOT`, `LIVE_SLOT`) are mapped read-only so derived queries can
  use them (`findByCustomerIdAndOpenSlot(customerId, 1)`).
- Compare-and-set: the adapter loads the row, checks `entity.getVersion() == domain.version()`,
  applies, `saveAndFlush`. `ObjectOptimisticLockingFailureException` or a version mismatch →
  "stale" (empty `Optional`), never an exception to the service.
- Multi-statement writes (`complete`: identity row + READY) are one `@Transactional` adapter
  method with `@Lock(PESSIMISTIC_WRITE)` on the registration row. Business conflicts are
  pre-checked with a query (`existsByUserNameIgnoreCase`) so the method returns a result, not
  a rolled-back exception. A lost race on the UNIQUE key is `RepositoryUnavailableException`
  → 503, and the row stays for reconciliation — the same policy as any unknown outcome.
- `@EnableJpaRepositories` and `@EntityScan` explicitly select
  `infrastructure.adapter.out.persistence.repository` and `infrastructure.adapter.out.persistence.entity`, respectively.
  New capability types go into these shared role packages; no capability scan package is added.
- Time columns are `DATETIME(6)` mapped to `Instant`; UUIDs are `BINARY(16)`.

---

## 9. Error-handling contract

| Source | Java type | Handled in | HTTP |
|---|---|---|---|
| Invalid request body / field | `MethodArgumentNotValidException`, `HttpMessageNotReadableException` | `GlobalExceptionHandler` | 400 `REQUEST_REJECTED` with sorted field details (never values) |
| Value object refused in a REST mapper | `InvalidRequestException` (`infrastructure.adapter.in.rest.common`) | `GlobalExceptionHandler` | 400 `REQUEST_REJECTED` |
| Business outcome | sealed `XxxResult` | REST mapper (`switch`) | 200 / 201 / 409 … per contract |
| Database down or race lost | `RepositoryUnavailableException` | service → `Unavailable` result, or handler if thrown outside a use case | 503 |
| Partner down / timeout / unexpected status | `PartnerUnavailableException` | service → `Unavailable` result | 503 (capability-specific code, e.g. `ACCOUNT_CREATION_UNAVAILABLE`) |
| Illegal state transition | `RegistrationStateException` | `GlobalExceptionHandler` | 500 `INTERNAL_ERROR` (a bug; logged with type only) |
| Anything else | `Exception` | `GlobalExceptionHandler` | 503 `TEMPORARILY_UNAVAILABLE` |

Rules: log exception types, never request values or secrets; responses never echo input;
every response carries `X-Correlation-Id` and `Cache-Control: no-store`.

### 9.1 Localized error messages (server-side, decided 2026-10-25)

The server is the only source of user-facing error text. The app shows `error.message` as is.

- **Locale**: from the `Accept-Language` header (`AcceptHeaderLocaleResolver`). Supported:
  `vi` (default) and `en`. A missing or unsupported language falls back to `vi`. Later, a
  logged-in customer's stored preference may override the header; the first login responses
  cannot rely on it.
- **Catalogue**: `messages/errors_<lang>.properties`, one line per error code
  (`IDENTITY_CONFLICT=Tên đăng nhập đã được sử dụng`). The properties files *are* the error
  catalogue: adding a code means adding a line in every language file, which a test enforces
  (same key set in all files; every code used in code exists in the catalogue).
- **Parameters**: `{0}`-style `MessageFormat` arguments for texts that carry numbers
  (e.g. remaining attempts); never a value the customer typed.
- **Where**: `infrastructure.adapter.in.rest.common.ErrorMessages` wraps Spring `MessageSource` and resolves
  `code` → text for `LocaleContextHolder.getLocale()`. REST mappers call
  `errors.failure(status, code, args...)` and no longer hold English text. A mapper therefore
  has a dependency and is an **instance created in config**, injected into its controller
  (the "static unless it needs a dependency" rule). `GlobalExceptionHandler` uses the same
  `ErrorMessages`; Bean Validation messages resolve through the same locale via
  `ValidationMessages_<lang>.properties`.
- **Security**: the text for a code is the same whatever the cause behind it (no "user not
  found" vs "wrong password" split); messages never echo input.
- **System-to-system endpoints** (e.g. registration callback) still go through the same
  path; they simply get the default language.

Envelope:

```json
{ "success": true,  "data": { ... } }
{ "success": false, "error": { "code": "IDENTITY_CONFLICT", "message": "...", "details": [ {"field": "...", "message": "..."} ] } }
```

---

## 10. Lombok policy **[arch]**

| Allowed | On | Why |
|---|---|---|
| `@Builder` (also `toBuilder = true`) | data records/classes with more than four fields: commands, port value types, aggregates, DTOs; not dependency construction for service beans | removes long positional data constructors without hiding behaviour |
| `@RequiredArgsConstructor` | services, controllers, adapters and other bean classes whose constructor only assigns required dependencies | generates constructor injection for uninitialized final fields (and required `@NonNull` fields); no field injection |
| `@NonNull` | required injected reference fields/parameters in those classes | generates a null check; final alone does not generate one; does not replace business or configuration validation |
| `@Getter`, `@Builder`, `@NoArgsConstructor(access = PROTECTED)`, `@AllArgsConstructor(access = PRIVATE)` | JPA entities, outbound partner DTOs | JPA needs a no-arg constructor; getters are boilerplate |

| Forbidden | Why |
|---|---|
| `@Data`, `@Setter` | hidden mutability; entities must change state only through named methods |
| `@EqualsAndHashCode`, `@ToString` | wrong on JPA proxies; may print secrets or personal data |
| `@Value` | records already do this |
| `@SneakyThrows`, `@Synchronized`, `val`/`var` | hide control flow |

Domain keeps its existing `@Builder` allowance and explicit invariant validation in
constructors/factories. Application additionally allows `@RequiredArgsConstructor` and
`@NonNull` for dependency injection; it still has no Spring/Jakarta annotations.

- Keep injected dependencies `private final`. Prefer `@RequiredArgsConstructor` when
  construction only assigns them; add `@NonNull` where a dependency must reject null.
  Without it, a generated constructor does not preserve an existing `requireNonNull` check.
- Keep an explicit constructor when it validates object invariants, performs conversion,
  makes defensive copies, or has other required initialization. Do not replace it mechanically.
- Runtime property validation belongs at the configuration boundary (§12), not in service
  constructors. Preserve domain invariant checks in domain types.
- Do not use `@AllArgsConstructor` as the default for services: it includes fields that
  are not required constructor dependencies. Its private JPA/data allowance above remains.
- An annotation removes repetitive assignments; it does not reduce the actual dependency
  count. Do not add dependency bags or split services solely to shorten a constructor in
  this business-flow phase.

Illustrative service composition; method bodies and unrelated dependencies omitted:

```java
// application.service — still plain Java, assembled by config
@RequiredArgsConstructor
public final class LoginService {
    @NonNull private final TrustedDeviceService trustedDeviceService;
}
```

Config can instantiate this class with `new LoginService(trustedDeviceService)`. The annotation
belongs on the class, not on an `@Bean` factory method. These new allowances require future
architecture-test updates; this documentation update does not enable them in source checks.

---

## 11. Naming conventions

| Thing | Pattern | Example |
|---|---|---|
| HTTP entry use case | `<Verb><Noun>UseCase` | `RegisterCustomerUseCase` |
| Command / result | `<Verb><Noun>Command`, `<Verb><Noun>Result` | `RegisterCustomerCommand` |
| Service | `<Verb><Noun>Service` for one operation, or `<Capability>Service` for cohesive operations | `RegisterCustomerService`, `TrustedDeviceService` |
| Outbound port | `<Noun>Port` or capability name in `port.out.gateway`; `<Noun>Repository` / `<Noun>Store` in `port.out.repository` | `IdentityProviderPort`, `TokenEnvelopeSealer`, `RegistrationRepository`, `SessionStore` |
| Outbound model / exception | meaningful contract noun in `port.out.model`; distinguished dependency failure in `port.out.exception` | `NewIdentityUser`, `CustomerProfile`, `PartnerUnavailableException` |
| Adapter | `<Tech><Noun>Adapter` | `KeycloakAdminAdapter`, `RegistrationPersistenceAdapter`, `ValkeySessionAdapter` |
| Servlet filter | `<Noun>Filter`, in `infrastructure.adapter.in.rest.common`; resolves its own locale and writes the envelope itself | `SessionFilter` |
| JPA entity / repository | `<Noun>Entity`, `<Noun>JpaRepository` | `RegistrationEntity` |
| REST DTO | `<Noun>Request`, `<Noun>Response` | `RegistrationRequest` |
| Mapper | `<Noun><Layer>Mapper` | `RegistrationRestMapper`, `RegistrationPersistenceMapper` |
| Configuration | `<Capability>Configuration`, `<Capability>Properties` | `RegistrationConfiguration` |
| Optional plain-Java application settings | `<Capability>Settings` | `RegistrationSettings` (only when a cohesive settings group is needed) |
| Business enum | business noun in `domain.enums`, no mandatory `Enum` suffix | `RegistrationState`, `DeviceStatus`, `TrustLevel` |
| Shared constant holder | specific purpose in the owning adapter's `constant` package | `ErrorCodes`, `KeycloakEndpoints`; not `Constants` or `CommonConstants` |
| Test | `<Class>Test` (unit), `<Class>IT` (needs Docker) | `RegisterCustomerServiceTest`, `RegistrationPersistenceAdapterIT` |

Method naming in mappers: `toCommand`, `toResponse`, `toEntity`, `toDomain`, `apply`.
Aggregate transitions are verbs in the event form the contract uses:
`markUserCreated`, `markSmsAccepted`, `complete`, `fail`.

Name service methods after business operations. A capability service may expose both reads
and updates; `Commands`/`Queries` interfaces and an interface per method are not required.

### 11.1 Enums, fixed constants and configurable properties

- Use `domain.enums` for business choices such as `RegistrationState`, `DeviceStatus`,
  `DevicePlatform` and `TrustLevel`. Aggregates/value objects stay in `domain.model` and
  import those enums. Enums have pure behavior, with no framework dependencies, I/O or
  stateful services.
- Keep small single-port outcomes, such as `RegistrationRepository.CompleteResult`, nested
  in their interface. Provider-only codes/enums stay in the owning adapter; mapping them
  inward does not turn provider protocol names into domain concepts.
- Preserve API/storage/signed enum codes independently of package moves. Never persist
  ordinals. Use explicit codecs or an intentionally frozen, tested name-based mapping;
  unknown security values must not default to an accepted state.
- Keep single-consumer literals `private static final`. When several classes within an
  adapter share fixed non-SQL literals, use a focused holder in that adapter's `constant`
  package: REST `ErrorCodes`, or partner `KeycloakEndpoints`, for example. A holder is final
  with a private constructor; no constant interfaces or service-wide `Constants` class.
  Reuse suitable framework/library constants. Create a package only when actual shared
  literals justify it; do not pre-create empty constant packages for every adapter.
- `ErrorCodes` belongs to `infrastructure.adapter.in.rest.constant`; `ErrorMessages` and
  error handling stay in `rest.common`. This is an ownership/package change, not a change
  to error codes, localization catalogue keys, status mapping or public messages.
- Provider-specific constants stay with that provider's adapter. SQL text retains its
  owning persistence repository's SQL holder rules; do not move native SQL into `constant`.
- Adjustable timeouts, request/session lifetimes and policy limits remain validated
  properties in `infrastructure.config`, passed to application as described in §12. Do not
  place secrets in constants or enums. Business enums, fixed literals and tunable policy
  values are distinct roles, not interchangeable ways to store the same setting.

### 11.2 Readable business steps and variable names

Follow [CODE_CONVENTIONS.md](CODE_CONVENTIONS.md) for the detailed rules and the trust/audit examples.

- Dependencies expose their role: `trustedDeviceRepository`, `trustedDeviceService`,
  `devicePolicy`, `registrationRestMapper`; collections describe their contents.
- Give meaningful business steps their own statements and name intermediate states.
  Build a nontrivial input before invoking a repository/partner; do not hide transitions,
  I/O or counter increments inside argument lists.
- In multi-field builders, put each field and `.build()` on separate lines. Separate
  mapping, persistence and result conversion when nesting would obscure execution order.
- Prefer clear flow over minimum line count. Do not add empty helpers, dependency bags
  or data wrappers just to shorten methods or call sites.
- These are review conventions, not claimed formatter/ArchUnit enforcement. Formatting
  alone does not establish business, transaction or concurrency correctness.

---

## 12. Configuration and wiring

- Business classes carry **no** Spring annotations. `infrastructure.config.<Capability>Configuration`
  creates them with `@Bean`, so the object graph of a feature is readable in one file.
- For cross-capability calls, inject the owning service class through the caller's
  constructor, e.g. `LoginService(TrustedDeviceService trustedDeviceService, ...)`. Expose the
  service bean by its concrete type for that injection; controller wiring still uses its
  inbound UseCase interface. Do not add service locators, circular wiring or forwarding beans.
- Adapters that need Spring proxies (`@Transactional`) are created as beans too, typed by
  their **port** interface so the proxy is interface-based.
- Each capability has a feature flag (`auth.<capability>.enabled`, default `false`) on its
  configuration class via `@ConditionalOnProperty`; off means no beans, no endpoint.
- Framework properties are validated records (`@ConfigurationProperties` + `@Validated`)
  under `infrastructure.config`; their `toString` hides secrets. Config owns property existence, bounds
  and cross-setting startup checks. A bad setting stops startup and names the property,
  never its value. This includes `requestLifetime > 0`; a service does not repeat that check.
- Application services do not import `RegistrationProperties` or other framework config
  classes, bind properties, read environment variables, or look up settings through the
  application context. Config passes the values they need through constructor injection.
- A single setting may be passed as its plain Java type, e.g. a validated `Duration` named
  `requestLifetime`. When several related business settings form a cohesive group, config
  maps them into an immutable plain-Java `RegistrationSettings` in `application.service`.
  The service reads `settings.requestLifetime()`. Do not create a one-field settings wrapper
  merely to shorten a constructor, or include collaborators, partner URLs or transport
  credentials in application settings. Configuration mechanics remain in `infrastructure.config`.
- `RestConfiguration` owns the `LocaleResolver` (Accept-Language, supported `vi`/`en`, default
  `vi`), the `MessageSource` for `messages/errors` and validation, and the response filters.
- Partner HTTP clients: one `RestClient` per partner, built in config with connect/read
  timeout and no redirects; no retries in code (the flow decides what may be retried).

---

## 13. Testing strategy

| Ring / piece | Test type | Tools | What it proves |
|---|---|---|---|
| `domain` | unit | JUnit, AssertJ | every legal and illegal transition, value validation, redaction |
| `application.service` | unit | Mockito ports and called capability services + in-memory repository double | flow order, published cross-capability outcomes, each failure leaves the right state, retries never call partners blindly |
| `mapper` | unit | JUnit | round trips, status/code table |
| `infrastructure.adapter.in.rest` | slice | `@WebMvcTest` with a `@MockitoBean` use case, `RestConfiguration` imported | envelope, headers, validation 400 details, status table, Accept-Language |
| `infrastructure.adapter.out.persistence` | integration | `@DataJpaTest` + Testcontainers MySQL 8.4 + Flyway | schema validation, unique keys, CAS, transactions |
| `infrastructure.adapter.out.<partner>` | unit | `MockRestServiceServer` | request shape, status mapping, timeout → unavailable |
| `infrastructure.config` | slice | `ApplicationContextRunner` | flag off = no beans; invalid values or missing required settings fail startup naming the key; validated properties map to the correct scalar/plain-Java settings |
| whole app | integration | `@SpringBootTest` + `@AutoConfigureMockMvc` + Testcontainers MySQL, the three partner **ports** replaced by `@MockitoBean` (partner HTTP is already proven by the adapter tests) | boot with Flyway + JPA validation, REST → use case → JPA → database, retry answered from the database |
| rules | static | ArchUnit | implemented §4, §10 and naming rules; new enum/constant ownership and pending layout rules require test updates in their implementation slices |

Conventions: a test class sits in the same package as the class under test; names read as
sentences (`aRetryAfterReadyReturnsTheSameRequestWithoutCallingAnyone`); tests needing Docker
end in `IT` and run in `mvn verify`, not `mvn test`.

These are test requirements for implementation slices, not results of this documentation
update. Architecture tests check role-only packages, inward layer dependencies and
direct/transitive service cycles. Repository/aggregate ownership within shared packages
is verified by business tests and class/method review, not inferred from package imports.
For the new target, check `application.port.in` contains only inbound interfaces, service
commands/results live in their dedicated packages, and controllers/mappers import those
contracts without importing services or outbound ports. Check outbound top-level types live
in `repository`, `gateway`, `model` or `exception`; outbound contracts must not depend on
service commands/results or implementations. REST package/mapper/config renames
also need explicit architecture-test updates; Spring's `@WebMvcTest` annotation keeps its name.
For infrastructure grouping, verify adapters/config use the new parent and domain/application
have no imports from `infrastructure`. Existing port ownership and runtime call order stay
unchanged; the parent package is not an additional workflow component.
For enum/constant changes, check business enums use `domain.enums`, provider enums stay
within adapters, and shared fixed literals have the appropriate owner. Before accepting
source moves, test that stored/wire enum codes and public error codes remain identical.
These enum/constant checks are implementation requirements, not results of this document edit.
Constructor-policy implementation checks must preserve required-dependency null checks,
allow the annotations in §10, and keep framework properties out of application. Tests for
configuration bounds (such as a zero/negative request lifetime) belong at startup binding/
wiring, while service tests receive already validated values. These checks are future slice
requirements, not executed test results here.

---

## 14. Security rules that shape the code

- Passwords and PINs exist only as method parameters or fields of objects whose `toString`
  is redacted; they are never stored, logged or returned.
- Request digests are keyed (HMAC) so a database copy cannot be reversed to a phone number.
- Partner calls happen only after their precondition is **saved**: a step whose outcome is
  unknown leaves the row where it is and the retry returns 503 for reconciliation.
- Internal endpoints are off by default; enabling them is a deployment decision per environment.
- Error messages never echo input; logs carry exception types and IDs, not payloads.

---

## 15. Adding a new capability — checklist

1. Design docs first: DB phase SQL + API contract exist and are approved.
2. `domain.model`: aggregate record with transitions and value objects; `domain.enums`:
   business enums; `domain.exception`: domain exceptions. Apply §11.1 for port/provider enums,
   constants and properties. No business subpackages. Unit test.
3. `application.command` / `application.result`: published operation inputs/outputs.
   `application.port.in`: UseCase interfaces for HTTP entry operations only, not for every
   method called by another service. Keep outbound-specific payloads with `port.out`.
4. `application.port.out.repository` / `gateway`: outbound interfaces; `model`: standalone
   input/output values; `exception`: distinguished dependency failures. Keep small single-port
   outcomes nested when useful. Do not introduce another copy of a service command (§5.1).
5. `application.service`: the service; inject other capability services only through
   their published entry points (§6.1), without cycles. Test with mocked ports/called services
   and an in-memory repository double. Use §10 for constructors and §11.2/code conventions
   for names and readable flow; preserve required null checks.
6. Flyway `V<n>__<phase>.sql` copied from the design phase file, unchanged.
7. `infrastructure.adapter.out.persistence`: add types to `entity`, `repository`, `mapper`, `adapter` by role;
   no capability subpackage. Verify with `@DataJpaTest` IT.
8. `infrastructure.adapter.out.<partner>` if a new partner: client, dto, mapper, `MockRestServiceServer` test.
9. `infrastructure.adapter.in.rest`: add types to `controller`, `dto.request`, `dto.response`, `mapper` by role;
   controller calls an inbound UseCase. Verify with `@WebMvcTest`.
10. `infrastructure.config.<Cap>Configuration` + `<Cap>Properties` with flag off by default; validate settings
    before injection, map a scalar or optional plain-Java settings group (§12); context-runner test.
11. Update `ArchitectureTest` for role-only packages, layer boundaries and service dependency
    cycles in the implementation slice, including the `infrastructure` parent and the ban
    on its imports in domain/application. Review business ownership at class/method level.
    Verify entities/repositories are covered by the existing explicit role-package scans,
    and enum/constant ownership checks reflect §11.1 while retaining existing external codes.
12. README: status, settings table, open gaps. ADR if a new technology decision was made.
    Review [CODE_CONVENTIONS.md](CODE_CONVENTIONS.md); formatters do not replace this review.

---

## 16. Representative code

```java
// application.port.in
// Imports: application.command.RegisterCustomerCommand, application.result.RegisterCustomerResult
public interface RegisterCustomerUseCase {
    RegisterCustomerResult register(RegisterCustomerCommand command);
}

// application.command
@Builder
public record RegisterCustomerCommand(CustomerId customerId, UserName userName, String firstName,
                                      String lastName, PhoneNumber phoneNumber, Email email) { }

// application.result
public sealed interface RegisterCustomerResult {
    record Ready(RegistrationId requestId, CustomerId customerId, UserName userName, boolean created)
            implements RegisterCustomerResult { }
    record IdentityConflict() implements RegisterCustomerResult { }
    record ProfileIncomplete() implements RegisterCustomerResult { }
    record Unavailable() implements RegisterCustomerResult { }
}

// domain.model — the state machine lives here; imports domain.enums.RegistrationState
@Builder(toBuilder = true)
public record Registration(RegistrationId id, CustomerId customerId, UserName userName,
                           RequestDigest requestDigest, RegistrationState state,
                           String identityIssuer, String identitySubject, Instant expiresAt, long version) {
    public Registration markUserCreated(String issuer, String subject) {
        requireState(RegistrationState.RESERVED);
        return toBuilder()
                .state(RegistrationState.USER_CREATED)
                .identityIssuer(issuer)
                .identitySubject(subject)
                .build();
    }
}

// application.port.out.repository
public interface RegistrationRepository {
    ReserveResult reserve(Registration reserved);
    Optional<Registration> findLatest(CustomerId customerId);
    Optional<Registration> save(Registration changed);      // empty = stale (compare-and-set)
    CompleteResult complete(Registration completed);        // identity row + READY, one transaction
}

// infrastructure.adapter.out.persistence.adapter — translates Spring exceptions; owns the one two-table transaction
@RequiredArgsConstructor
public class RegistrationPersistenceAdapter implements RegistrationRepository {
    @NonNull private final RegistrationJpaRepository registrationJpaRepository;
    @NonNull private final CustomerAuthenticationJpaRepository customerAuthenticationJpaRepository;

    @Override
    public Optional<Registration> save(Registration changed) {            // compare-and-set via @Version
        try {
            Optional<RegistrationEntity> currentRegistration = registrationJpaRepository.findById(changed.id().value());
            if (currentRegistration.isEmpty() || currentRegistration.get().getVersion() != changed.version()) {
                return Optional.empty();
            }

            RegistrationEntity registrationEntity = currentRegistration.get();
            RegistrationPersistenceMapper.apply(registrationEntity, changed);

            RegistrationEntity savedRegistration = registrationJpaRepository.saveAndFlush(registrationEntity);
            Registration restoredRegistration = RegistrationPersistenceMapper.toDomain(savedRegistration);
            return Optional.of(restoredRegistration);
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }

    @Override
    @Transactional                                                        // identity row + READY together
    public CompleteResult complete(Registration completed) { … }
}

// infrastructure.adapter.in.rest.controller — a controller is glue: map in, call the use case, map out
@RestController
@RequiredArgsConstructor
public class RegistrationController {
    @NonNull private final RegisterCustomerUseCase registerCustomerUseCase;
    @NonNull private final RegistrationRestMapper registrationRestMapper;

    @PostMapping(path = "/internal/v1/callback/authentication-creation",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<RegistrationResponse>> create(@Valid @RequestBody RegistrationRequest body) {
        RegisterCustomerCommand registrationCommand = registrationRestMapper.toCommand(body);
        RegisterCustomerResult registrationResult = registerCustomerUseCase.register(registrationCommand);
        return registrationRestMapper.toResponse(registrationResult);
    }
}

// infrastructure.adapter.in.rest.mapper — an instance because the text comes from ErrorMessages (§9.1)
// Imports: infrastructure.adapter.in.rest.constant.ErrorCodes
@RequiredArgsConstructor
public final class RegistrationRestMapper {
    @NonNull private final ErrorMessages errorMessages;

    /** Bean Validation already rejected bad formats; a value object that still refuses is a 400. */
    public RegisterCustomerCommand toCommand(RegistrationRequest request) {
        try {
            return RegisterCustomerCommand.builder()
                    .customerId(new CustomerId(request.customerId()))
                    .userName(new UserName(request.userName()))
                    .firstName(request.firstName())
                    .lastName(request.lastName())
                    .phoneNumber(new PhoneNumber(request.phoneNumber()))
                    .email(blank(request.email()) ? null : new Email(request.email()))
                    .build();
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());   // → 400 REQUEST_REJECTED
        }
    }

    public ResponseEntity<ApiEnvelope<RegistrationResponse>> toResponse(RegisterCustomerResult result) {
        return switch (result) {
            case Ready ready -> {
                HttpStatus responseStatus = ready.created() ? HttpStatus.CREATED : HttpStatus.OK;
                RegistrationResponse registrationResponse = new RegistrationResponse(
                        ready.requestId().value(),
                        ready.customerId().value(),
                        ready.userName().value(),
                        "READY");

                yield ResponseEntity.status(responseStatus)
                        .body(ApiEnvelope.success(registrationResponse));
            }
            case IdentityConflict() -> errorMessages.failure(
                    HttpStatus.CONFLICT,
                    ErrorCodes.IDENTITY_CONFLICT);
            case ProfileIncomplete() -> errorMessages.failure(
                    HttpStatus.CONFLICT,
                    ErrorCodes.CUSTOMER_PROFILE_INCOMPLETE);
            case Unavailable() -> errorMessages.failure(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    ErrorCodes.ACCOUNT_CREATION_UNAVAILABLE);
        };
    }
}
```

---

## 17. Decisions log (short ADRs)

| Date | Decision | Reason | Alternative rejected |
|---|---|---|---|
| 2026-10-25 | Spring Data JPA for persistence | entities + `ddl-auto=validate` keep code and schema in sync; `@Version` gives CAS; repositories are declarative | `JdbcClient` plain SQL (no mapping layer, hand-written CAS) |
| 2026-10-25 | Hand-written mappers | readable, debuggable, no annotation processor; MapStruct not available offline | MapStruct |
| 2026-10-25 | Scoped Lombok constructors and builders | `@Builder` for data; `@RequiredArgsConstructor` and optional `@NonNull` for assignment-only bean constructors; explicit constructors retain initialization/invariant logic | all handwritten assignment-only constructors; blanket `@AllArgsConstructor`; unrestricted Lombok |
| 2026-10-25 | Validate configuration before service construction | config validates framework properties and passes a scalar or cohesive plain-Java settings group; application remains framework-independent | importing framework properties into application; repeated property checks in service constructors; one-field settings/dependency bags |
| 2026-10-25 | Inbound use-case interfaces for controllers | HTTP entry contracts remain separate; internal calls use service classes | controller calls the service class; interface per internal method |
| 2026-10-25 | Separate application operation contracts | `application.port.in` holds UseCase interfaces only; commands/input values go to `application.command`, results/output values to `application.result`; outbound-specific contracts stay with `port.out` | commands/results mixed with inbound interfaces; application HTTP DTOs |
| 2026-10-25 | Outbound contracts grouped by role | `port.out.repository` and `gateway` hold interfaces, `model` holds standalone dependency input/output values, `exception` holds distinguished dependency failures; service commands remain separate | flat outbound package; business subpackages; duplicate commands or forwarding payload wrappers |
| 2026-10-25 | REST naming for the HTTP inbound adapter | `infrastructure.adapter.in.rest`, `*RestMapper` and `RestConfiguration` describe the supported API surface | `infrastructure.adapter.in.web`, `*WebMapper` and `WebConfiguration` as target names |
| 2026-10-25 | Common infrastructure parent | `infrastructure.adapter` holds technical adapters and `infrastructure.config` assembles them; domain/application never import infrastructure; ports remain application-owned | root adapter/config packages; moving core ports into infrastructure; an extra runtime layer |
| 2026-10-25 | Business enums and owned constants | business enums use `domain.enums`; single-port outcomes and provider enums retain their owners; private or adapter-scoped fixed literals stay separate from configurable properties; package moves preserve external codes | business enums mixed into model; one global enum/constants dump; adjustable policy as constants |
| 2026-10-25 | Explicit business steps and role-based variable names | CODE_CONVENTIONS.md requires readable builders, named intermediate states, visible effects and descriptive dependencies; clarity takes priority over line count | compressed effectful expressions; ambiguous dependency names; arbitrary helper extraction |
| 2026-10-25 | Direct service calls between capabilities | the owning service exposes cohesive business operations through constructor injection and published commands/results; no cycles | calls through another capability's repository; forwarding interfaces; internal HTTP hops |
| 2026-10-25 | Role-only layer-first packages throughout | domain/application/rest/persistence group by role; class names and contracts express business ownership; supersedes the earlier mixed capability/role layout | business subpackages in domain/application/rest/persistence; a separate domain.shared package |
| 2026-10-25 | Cohesive service operations without required CQRS | an operation may read, validate, update and return data; the owning capability keeps its rules | mandatory Commands/Queries interfaces or a UseCase for every method |
| 2026-10-25 | Keys-only database | rules in code, UNIQUE for races only; schema stays simple to evolve | CHECK/FK constraints |
| 2026-10-25 | Server-side localized error messages, `vi` default + `en`, by `Accept-Language` | one source of truth for all channels; message catalogue reviewable per language | app-side localization; code-only responses |
