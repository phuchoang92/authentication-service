# Authentication Service v2 — Codebase Architecture

Status: **target design, approved 2026-10-25**. The code is being moved onto it slice by
slice; "current" notes below say where the code still differs. **[arch]** marks rules intended
for `ArchitectureTest`; it is not proof that a rule is already enforced. Direct service
calls between services and role-based domain/application/web/persistence packages are
documentation targets in this update; no source or architecture tests are changed.

This phase builds the business flow bottom-up. It adds no CAS, concurrency or performance
design; the existing registration, persistence and security contracts remain unchanged.

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

The code is split into four **rings**. Dependencies between rings point inward; config
assembles them. Services within the application ring may call each other as described in §6.1.

```text
            ┌──────────────────────────── adapter.in ───────────────────────────┐
            │  HTTP in: controllers, request/response DTOs, web mappers          │
            │   ┌────────────────────────── application ──────────────────────┐  │
            │   │  use cases (port.in), outbound ports (port.out), services    │  │
            │   │   ┌──────────────────────── domain ───────────────────────┐  │  │
            │   │   │  aggregates, value objects, enums, domain exceptions  │  │  │
            │   │   └───────────────────────────────────────────────────────┘  │  │
            │   └─────────────────────────────────────────────────────────────┘  │
            └───────────────────────────────────────────────────────────────────┘
            ┌──────────────────────────── adapter.out ──────────────────────────┐
            │  JPA entities + repositories, HTTP partner clients, their DTOs     │
            └───────────────────────────────────────────────────────────────────┘
            ┌──────────────────────────── config ───────────────────────────────┐
            │  Spring wiring; sees everything, contains no logic                 │
            └───────────────────────────────────────────────────────────────────┘
```

Direction of dependencies:

```text
adapter.in  ──► application.port.in  ──► domain
application.service.LoginService ──► application.service.TrustedDeviceService
                                  + published application.port.in values
adapter.out ──► application.port.out ──► domain
config      ──► all rings (creates beans)
```

**Layer-first throughout** means domain, application, web and persistence are grouped by
role, without business subpackages such as `registration`, `login`, `session` or
`trusteddevice`. Business ownership is expressed by class names and responsibilities,
not folders: `Registration`, `LoginService`, `TrustedDeviceService`, and their contracts.
All domain values, including values used by several flows, live in `domain.model`; no
separate `domain.shared` package is needed.
Partner adapters remain grouped by external system (`customer`, `keycloak`, `notification`).

---

## 3. Package layout

```text
com.vpbank.dcp.auth
├── AuthenticationApplication                 @SpringBootApplication, nothing else
│
├── domain                                    ring 1 — pure Java
│   ├── model                                 Registration (aggregate), RegistrationState,
│   │                                         RegistrationId, RequestDigest,
│   │                                         CustomerId, UserName, PhoneNumber, Email
│   └── exception                             RegistrationStateException
│
├── application                               ring 2 — pure Java, orchestrates the domain
│   ├── port
│   │   ├── in                                RegisterCustomerUseCase,
│   │   │                                     RegisterCustomerCommand, RegisterCustomerResult
│   │   └── out                               RegistrationRepository, CustomerDirectoryPort,
│   │                                         IdentityProviderPort, SmsSenderPort,
│   │                                         NewIdentityUser, InitialPasswordSms, CustomerProfile,
│   │                                         RepositoryUnavailableException,
│   │                                         PartnerUnavailableException
│   └── service                               RegisterCustomerService (implements the use case),
│                                             RequestDigester, InitialPasswordGenerator
│                                             Later, when implemented: LoginService, TrustedDeviceService
│
├── adapter
│   ├── in
│   │   └── web                               ring 3 — Spring MVC
│   │       ├── common                        ApiEnvelope, ApiError, FieldDetail, InvalidRequestException,
│   │       │                                 GlobalExceptionHandler, ResponseHeadersFilter,
│   │       │                                 ErrorMessages (localized text by error code)
│   │       ├── controller                    RegistrationController
│   │       ├── dto
│   │       │   ├── request                   RegistrationRequest
│   │       │   └── response                  RegistrationResponse
│   │       └── mapper                        RegistrationWebMapper
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
│       │   ├── dto                           TokenResponse, CreateUserRequest, CredentialRequest,
│       │   │                                 EnableUserRequest
│       │   └── mapper                        KeycloakUserMapper
│       └── notification
│           ├── NotificationHttpAdapter       implements SmsSenderPort
│           ├── dto                           SmsRequest, SmsResponse
│           └── mapper                        SmsMapper
│
└── config                                    ring 4 — Spring only
      WebConfiguration (LocaleResolver, MessageSource, filters),
      JpaConfiguration, RegistrationConfiguration, RegistrationProperties

src/main/resources
├── messages/errors_vi.properties             error code → Vietnamese text (default language)
├── messages/errors_en.properties             error code → English text
└── ValidationMessages_vi.properties, ValidationMessages_en.properties   Bean Validation texts
```

**Current (2026-10-25, after the refactor to this document):** the code matches the tree
above. Persistence is Spring Data JPA (`RegistrationEntity`, `CustomerAuthenticationEntity`,
two `JpaRepository` interfaces, `RegistrationPersistenceMapper`, `RegistrationPersistenceAdapter`
plus `RegistrationCompletion` holding the one two-table `@Transactional` step) with
`ddl-auto=validate` against the Flyway schema. Error messages are localized (§9.1): `ErrorCodes`,
`ErrorMessages`, `messages/errors_vi|en.properties`, `ValidationMessages_vi|en.properties`;
`RegistrationWebMapper` is an instance created in `RegistrationConfiguration`. Partner adapters
have `dto` and `mapper` packages. `RegistrationConfiguration` exposes one bean per outbound port.
`ApplicationBootIT` boots the whole application against MySQL with the ports mocked. Still
illustrative only: Login and Trusted Device examples below.

---

## 4. What each ring contains, and what it may import

| Ring | Package | Contains | May import | Must not import **[arch]** |
|---|---|---|---|---|
| Domain | `domain..` | `model` (aggregates, value objects, enums), `exception` | `java..`, `lombok.Builder`, domain types | Spring, Jakarta, `application`, `adapter`, `config` |
| Application | `application..` | `port.in` (HTTP use case + published commands/results), `port.out` (interfaces + their value types + unavailability exceptions), `service` (including optional plain-Java settings) | domain types for its own business rules, shared domain values, its own outbound ports and helpers, other services and published `port.in` commands/results (§6.1), `java..`, `javax.crypto..`, `lombok.Builder`; `lombok.RequiredArgsConstructor` and `lombok.NonNull` for constructor injection (§10) | Spring, Jakarta, `adapter`, `config` (including framework properties); bypassing another service's ownership through its repository or internal aggregate |
| Adapter in | `adapter.in..` | controllers, request/response DTOs, web mappers, envelope, error handler, filters | `application..port.in`, domain values for web mapping only, Spring MVC, Jakarta Validation | `adapter.out..`, JPA entities, `application..service`; controllers also follow the narrower rule below |
| Adapter out | `adapter.out..` | JPA entities + Spring Data repositories + persistence adapter; HTTP clients + wire DTOs + adapter | `application..port.out`, `domain..`, Spring Data / JPA / RestClient | `adapter.in..`, another `adapter.out.<x>` package, `application..service` |
| Config | `config` | `@Configuration`, `@ConfigurationProperties` | everything | business logic (no `if` on business data) |

Additional **[arch]** rules:

- **Controllers are glue** (convention, reviewed): bind path/headers/body, `toCommand(...)`,
  call the use case, `toResponse(result)`. A controller never decides a business outcome or
  an HTTP status; the result → status/code table is a mapping and lives in `toResponse`.
  Transport-only headers (e.g. `Set-Cookie`) may be added by the controller. Trivial endpoints
  still get a mapper, so the mapping is always in the same place. Mappers are static; one
  becomes a bean only when it needs a dependency.
- **[arch]** A controller depends only on `application..port.in`, web `dto`/`mapper`,
  `adapter.in.web.common` and Spring MVC — never on `domain..model`, `port.out`, `service`
  or entities.
- A class whose name ends in `Request` or `Response` lives in a `dto` package (web or partner).
- A class whose name ends in `Mapper` lives in a `mapper` package and is `final`; static methods
  unless it needs a dependency such as `ErrorMessages`, then an instance created in config.
- A class whose name ends in `Entity` lives in `adapter.out.persistence..entity`.
- A class whose name ends in `UseCase` lives in `application..port.in`; one ending in `Port`
  lives in `application..port.out`.
- An application service may call another capability's published service class directly,
  using constructor injection and its published `port.in` commands/results (§6.1). No
  cross-capability repository access, internal domain access, or circular service dependencies.
- Domain, application, web and persistence use role packages only. A capability denotes
  logical business ownership, not a package. Service ownership rules are reviewed at class
  and method level; shared role packages do not enforce those rules by themselves.
- Lombok allow-list, see §10.

---

## 5. Type catalogue — where does a new class go?

| You are writing… | It goes to | Shape |
|---|---|---|
| A thing with identity and a lifecycle (registration, session, device) | `domain.model` | immutable `record`, `@Builder(toBuilder = true)`, named transition methods returning a new instance |
| A validated small value (customer ID, phone, PIN length) | `domain.model` | `record` with compact constructor that throws `IllegalArgumentException`; `toString` redacts personal data |
| A fixed list (states, statuses) | `domain.model` | `enum`, with helper methods such as `finished()` |
| "This step is not allowed from this state" | `domain.exception` | extends `IllegalStateException`; a bug, mapped to 500 |
| Published input to a service operation | `application.port.in` | `XxxCommand` record (`@Builder` if > 4 fields), used by HTTP use cases or direct service callers; no other capability's internal domain types |
| Published output of a service operation | `application.port.in` | `sealed interface XxxResult` when outcomes differ; immutable values, not entities or internal aggregates; business failures are outcomes, not exceptions |
| HTTP entry contract | `application.port.in` | `XxxUseCase` interface invoked by a controller; no interface required for every public service method |
| Business operation or cohesive group of operations | `application.service` | `final class XxxService`; implements a UseCase for HTTP entry operations; final dependencies, `@RequiredArgsConstructor` for assignment-only construction or an explicit constructor for initialization logic (§10); no Spring annotations |
| Cohesive application settings, when needed | `application.service` | immutable plain-Java `XxxSettings` record; created from validated properties in config (§12), no Spring/Jakarta annotations or collaborator fields; no wrapper required for one setting |
| Something outside we call (DB, partner, clock, random) | `application.port.out` | `interface XxxPort` / `XxxRepository`; parameters > 4 become a `@Builder` record next to it |
| "The outside did not answer" | `application.port.out` | `RepositoryUnavailableException`, `PartnerUnavailableException`; service catches → `Unavailable` result |
| HTTP entry point | `adapter.in.web.controller` | controller invokes an inbound UseCase, never a concrete service |
| HTTP body in | `adapter.in.web.dto.request` | `record` with Jakarta Validation; strings only; `toString` redacted |
| HTTP body out | `adapter.in.web.dto.response` | `record`; strings and primitives only |
| Request → command, result → `ResponseEntity` | `adapter.in.web.mapper` | `final class XxxWebMapper` with `toCommand`, `toResponse`; static unless it needs a dependency (`ErrorMessages`), then created in config |
| Table row | `adapter.out.persistence.entity` | JPA class, see §8 |
| Query | `adapter.out.persistence.repository` | `interface extends JpaRepository`, derived queries, `@Lock` where needed |
| Entity ↔ domain | `adapter.out.persistence.mapper` | `final class XxxPersistenceMapper` static `toEntity`, `toDomain`, `apply(entity, domain)` |
| Port implementation over JPA | `adapter.out.persistence.adapter` | `@Transactional` class; translates Spring exceptions into port exceptions/results |
| Partner JSON | `adapter.out.<partner>.dto` | `record`s named after the partner's payloads; Lombok `@Builder` allowed |
| Partner JSON ↔ port value types | `adapter.out.<partner>.mapper` | `final class` static methods |
| Bean wiring and framework properties | `config` | one `XxxConfiguration` per capability; `XxxProperties` as validated records; maps to plain-Java settings or a scalar before injection into application (§12) |

---

## 6. One request, top to bottom (registration)

```text
POST /internal/v1/callback/authentication-creation
  │
  ▼ adapter.in.web.controller.RegistrationController
  │   @Valid RegistrationRequest (dto.request)          ← 400 REQUEST_REJECTED if invalid
  │   RegistrationWebMapper.toCommand(request)          ← builds CustomerId, UserName, PhoneNumber, Email
  ▼ application.port.in.RegisterCustomerUseCase.register(command)
  │
  ▼ application.service.RegisterCustomerService
  │   digester.digest(command)                           RequestDigester (HMAC-SHA256)
  │   registrations.findLatest(customerId)               RegistrationRepository (port.out)
  │   customers.profile(customerId)                      CustomerDirectoryPort
  │   Registration.reserve(...)  → registrations.reserve  domain creates, adapter stores
  │   identities.createDisabledUser(NewIdentityUser)     IdentityProviderPort
  │   registrations.save(reg.markUserCreated(iss, sub))  domain transition, adapter CAS
  │   identities.setPassword(sub, password)
  │   sms.sendInitialPassword(InitialPasswordSms)        SmsSenderPort
  │   registrations.save(reg.markSmsAccepted())
  │   identities.enable(sub)
  │   registrations.complete(reg.complete())             one DB transaction: identity row + READY
  │   → RegisterCustomerResult.Ready / IdentityConflict / ProfileIncomplete / Unavailable
  ▼
  adapter.in.web.mapper.RegistrationWebMapper.toResponse(result)
      Ready(created=true)  → 201 {success:true, data:{requestId, customerId, userName, state:"READY"}}
      Ready(created=false) → 200 same body
      IdentityConflict     → 409 IDENTITY_CONFLICT
      ProfileIncomplete    → 409 CUSTOMER_PROFILE_INCOMPLETE
      Unavailable          → 503 ACCOUNT_CREATION_UNAVAILABLE
```

Reading rule: a reviewer reads **controller → mapper → service → domain → adapter** and never
needs to open `config` to understand behaviour.

### 6.1 Calls between services in the same application

The application service owns the sequence of business steps. It calls domain objects for
rules and transitions, its own outbound ports for technology boundaries, and another
capability's service when it needs that capability's business operations.

Illustrative future Login → Trusted Device flow (not an implemented login contract):

```text
LoginController                         adapter.in.web.controller
  → LoginUseCase                        application.port.in
  → LoginService                        application.service
      → TrustedDeviceService            application.service
          → TrustedDeviceRepository     application.port.out
          → TrustedDevicePersistenceAdapter  adapter.out.persistence.adapter
          → DB
```

- Inject `TrustedDeviceService` into `LoginService` through its constructor. This is an
  ordinary Java call in the same application; no HTTP hop or forwarding interface is needed.
  Controllers still call inbound UseCase interfaces, not service classes.
- Services share `application.service`; their published commands/results share
  `application.port.in`. These packages do not imply shared business ownership. Call only
  the owning service's published entry points, not its helpers. Public signatures use shared
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
| 1 | Ports & Adapters | technology swap and isolated tests | `port.out` interfaces, `adapter.out` implementations |
| 2 | Inbound UseCase for HTTP entry | the controller depends on an entry contract; internal service calls use classes without an interface per method | `port.in`, `service` |
| 3 | Command / Result objects | no long parameter lists; outcomes are explicit and exhaustive (`switch` on sealed type) | `port.in` |
| 4 | Sealed results, not business exceptions | a conflict is a normal answer, not a stack trace; the compiler checks every case is handled | `port.in`, web mapper |
| 5 | Rich aggregate | the state machine is in one file with one test; adapters cannot bypass it | `domain.model` |
| 6 | Compare-and-set versioning | two concurrent calls never both advance a row; `@Version` in JPA, the domain carries the expected version | aggregate + persistence adapter |
| 7 | Mapper per adapter | wire/table shapes never leak into domain; each mapping is a table a reviewer can read; static unless it needs a dependency (e.g. `ErrorMessages`) | `mapper` packages |
| 8 | Transaction at the adapter | no SQL transaction spans an HTTP call to a partner; services stay plain classes | `@Transactional` on persistence adapters only |
| 9 | Configuration per capability | the whole object graph of one feature is one file; feature flag in one place | `config.XxxConfiguration` |
| 10 | Envelope + global error handler | one response shape; infrastructure errors mapped once | `adapter.in.web.common` |
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
    @Column(name = "OPEN_SLOT", insertable = false, updatable = false) private Integer openSlot; // generated column
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
  `adapter.out.persistence.repository` and `adapter.out.persistence.entity`, respectively.
  New capability types go into these shared role packages; no capability scan package is added.
- Time columns are `DATETIME(6)` mapped to `Instant`; UUIDs are `BINARY(16)`.

---

## 9. Error-handling contract

| Source | Java type | Handled in | HTTP |
|---|---|---|---|
| Invalid request body / field | `MethodArgumentNotValidException`, `HttpMessageNotReadableException` | `GlobalExceptionHandler` | 400 `REQUEST_REJECTED` with sorted field details (never values) |
| Value object refused in a web mapper | `InvalidRequestException` (`adapter.in.web.common`) | `GlobalExceptionHandler` | 400 `REQUEST_REJECTED` |
| Business outcome | sealed `XxxResult` | web mapper (`switch`) | 200 / 201 / 409 … per contract |
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
- **Where**: `adapter.in.web.common.ErrorMessages` wraps Spring `MessageSource` and resolves
  `code` → text for `LocaleContextHolder.getLocale()`. Web mappers call
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
    @NonNull private final TrustedDeviceService trustedDevices;
}
```

Config can instantiate this class with `new LoginService(trustedDevices)`. The annotation
belongs on the class, not on an `@Bean` factory method. These new allowances require future
architecture-test updates; this documentation update does not enable them in source checks.

---

## 11. Naming conventions

| Thing | Pattern | Example |
|---|---|---|
| HTTP entry use case | `<Verb><Noun>UseCase` | `RegisterCustomerUseCase` |
| Command / result | `<Verb><Noun>Command`, `<Verb><Noun>Result` | `RegisterCustomerCommand` |
| Service | `<Verb><Noun>Service` for one operation, or `<Capability>Service` for cohesive operations | `RegisterCustomerService`, `TrustedDeviceService` |
| Outbound port | `<Noun>Port` for partners, `<Noun>Repository` for storage | `IdentityProviderPort`, `RegistrationRepository` |
| Adapter | `<Tech><Noun>Adapter` | `KeycloakAdminAdapter`, `RegistrationPersistenceAdapter` |
| JPA entity / repository | `<Noun>Entity`, `<Noun>JpaRepository` | `RegistrationEntity` |
| Web DTO | `<Noun>Request`, `<Noun>Response` | `RegistrationRequest` |
| Mapper | `<Noun><Layer>Mapper` | `RegistrationWebMapper`, `RegistrationPersistenceMapper` |
| Configuration | `<Capability>Configuration`, `<Capability>Properties` | `RegistrationConfiguration` |
| Optional plain-Java application settings | `<Capability>Settings` | `RegistrationSettings` (only when a cohesive settings group is needed) |
| Test | `<Class>Test` (unit), `<Class>IT` (needs Docker) | `RegisterCustomerServiceTest`, `RegistrationPersistenceAdapterIT` |

Method naming in mappers: `toCommand`, `toResponse`, `toEntity`, `toDomain`, `apply`.
Aggregate transitions are verbs in the event form the contract uses:
`markUserCreated`, `markSmsAccepted`, `complete`, `fail`.

Name service methods after business operations. A capability service may expose both reads
and updates; `Commands`/`Queries` interfaces and an interface per method are not required.

---

## 12. Configuration and wiring

- Business classes carry **no** Spring annotations. `config.<Capability>Configuration`
  creates them with `@Bean`, so the object graph of a feature is readable in one file.
- For cross-capability calls, inject the owning service class through the caller's
  constructor, e.g. `LoginService(TrustedDeviceService trustedDevices, ...)`. Expose the
  service bean by its concrete type for that injection; controller wiring still uses its
  inbound UseCase interface. Do not add service locators, circular wiring or forwarding beans.
- Adapters that need Spring proxies (`@Transactional`) are created as beans too, typed by
  their **port** interface so the proxy is interface-based.
- Each capability has a feature flag (`auth.<capability>.enabled`, default `false`) on its
  configuration class via `@ConditionalOnProperty`; off means no beans, no endpoint.
- Framework properties are validated records (`@ConfigurationProperties` + `@Validated`)
  under `config`; their `toString` hides secrets. Config owns property existence, bounds
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
  credentials in application settings. Configuration mechanics remain in `config`.
- `WebConfiguration` owns the `LocaleResolver` (Accept-Language, supported `vi`/`en`, default
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
| `adapter.in.web` | slice | `@WebMvcTest` with a mocked use case | envelope, headers, validation 400 details, status table |
| `adapter.out.persistence` | integration | `@DataJpaTest` + Testcontainers MySQL 8.4 + Flyway | schema validation, unique keys, CAS, transactions |
| `adapter.out.<partner>` | unit | `MockRestServiceServer` | request shape, status mapping, timeout → unavailable |
| `config` | slice | `ApplicationContextRunner` | flag off = no beans; invalid values or missing required settings fail startup naming the key; validated properties map to the correct scalar/plain-Java settings |
| whole app | integration | `@SpringBootTest` + Testcontainers + `MockRestServiceServer` | one happy path end to end |
| rules | static | ArchUnit | implemented §4, §10 and naming rules; role-only packages, layer boundaries and service cycles require future test updates |

Conventions: a test class sits in the same package as the class under test; names read as
sentences (`aRetryAfterReadyReturnsTheSameRequestWithoutCallingAnyone`); tests needing Docker
end in `IT` and run in `mvn verify`, not `mvn test`.

These are test requirements for implementation slices, not results of this documentation
update. Architecture tests check role-only packages, inward layer dependencies and
direct/transitive service cycles. Repository/aggregate ownership within shared packages
is verified by business tests and class/method review, not inferred from package imports.
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
2. `domain.model`: aggregate record with transitions, value objects and enums;
   `domain.exception`: domain exceptions. No business subpackages. Unit test.
3. `application.port.in`: published commands/results; add a UseCase interface for HTTP
   entry operations, not for every method called by another service.
4. `application.port.out`: one interface per outside thing; value types with `@Builder`.
5. `application.service`: the service; inject other capability services only through
   their published entry points (§6.1), without cycles. Test with mocked ports/called services
   and an in-memory repository double. Use §10 for constructors; preserve required null checks.
6. Flyway `V<n>__<phase>.sql` copied from the design phase file, unchanged.
7. `adapter.out.persistence`: add types to `entity`, `repository`, `mapper`, `adapter` by role;
   no capability subpackage. Verify with `@DataJpaTest` IT.
8. `adapter.out.<partner>` if a new partner: client, dto, mapper, `MockRestServiceServer` test.
9. `adapter.in.web`: add types to `controller`, `dto.request`, `dto.response`, `mapper` by role;
   controller calls an inbound UseCase. Verify with `@WebMvcTest`.
10. `config.<Cap>Configuration` + `<Cap>Properties` with flag off by default; validate settings
    before injection, map a scalar or optional plain-Java settings group (§12); context-runner test.
11. Update `ArchitectureTest` for role-only packages, layer boundaries and service dependency
    cycles in the implementation slice. Review business ownership at class/method level.
    Verify entities/repositories are covered by the existing explicit role-package scans.
12. README: status, settings table, open gaps. ADR if a new technology decision was made.

---

## 16. Representative code

```java
// application.port.in
public interface RegisterCustomerUseCase {
    RegisterCustomerResult register(RegisterCustomerCommand command);
}

@Builder
public record RegisterCustomerCommand(CustomerId customerId, UserName userName, String firstName,
                                      String lastName, PhoneNumber phoneNumber, Email email) { }

public sealed interface RegisterCustomerResult {
    record Ready(RegistrationId requestId, CustomerId customerId, UserName userName, boolean created)
            implements RegisterCustomerResult { }
    record IdentityConflict() implements RegisterCustomerResult { }
    record ProfileIncomplete() implements RegisterCustomerResult { }
    record Unavailable() implements RegisterCustomerResult { }
}

// domain.model — the state machine lives here
@Builder(toBuilder = true)
public record Registration(RegistrationId id, CustomerId customerId, UserName userName,
                           RequestDigest requestDigest, RegistrationState state,
                           String identityIssuer, String identitySubject, Instant expiresAt, long version) {
    public Registration markUserCreated(String issuer, String subject) {
        requireState(RegistrationState.RESERVED);
        return toBuilder().state(RegistrationState.USER_CREATED)
                .identityIssuer(issuer).identitySubject(subject).build();
    }
}

// application.port.out
public interface RegistrationRepository {
    ReserveResult reserve(Registration reserved);
    Optional<Registration> findLatest(CustomerId customerId);
    Optional<Registration> save(Registration changed);      // empty = stale (compare-and-set)
    CompleteResult complete(Registration completed);        // identity row + READY, one transaction
}

// adapter.out.persistence.adapter — owns the transaction and the mapping
@Transactional
public class RegistrationPersistenceAdapter implements RegistrationRepository {
    @Override
    public Optional<Registration> save(Registration changed) {
        try {
            RegistrationEntity entity = registrations.findById(changed.id().value()).orElseThrow();
            if (entity.getVersion() != changed.version()) {
                return Optional.empty();
            }
            RegistrationPersistenceMapper.apply(entity, changed);
            return Optional.of(RegistrationPersistenceMapper.toDomain(registrations.saveAndFlush(entity)));
        } catch (ObjectOptimisticLockingFailureException stale) {
            return Optional.empty();
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}

// adapter.in.web.controller — a controller is glue: map in, call the use case, map out
@RestController
public class RegistrationController {
    private final RegisterCustomerUseCase registerCustomer;

    @PostMapping(path = "/internal/v1/callback/authentication-creation",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<RegistrationResponse>> create(@Valid @RequestBody RegistrationRequest body) {
        RegisterCustomerCommand command = RegistrationWebMapper.toCommand(body);
        RegisterCustomerResult result = registerCustomer.register(command);
        return RegistrationWebMapper.toResponse(result);
    }
}

// adapter.in.web.mapper — validation of values happens here, as 400
public final class RegistrationWebMapper {
    private RegistrationWebMapper() { }

    /** Bean Validation already rejected bad formats; a value object that still refuses is a 400. */
    public static RegisterCustomerCommand toCommand(RegistrationRequest request) {
        try {
            return RegisterCustomerCommand.builder()
                    .customerId(new CustomerId(request.customerId()))
                    .userName(new UserName(request.userName()))
                    .firstName(request.firstName()).lastName(request.lastName())
                    .phoneNumber(new PhoneNumber(request.phoneNumber()))
                    .email(request.email() == null || request.email().isBlank() ? null : new Email(request.email()))
                    .build();
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());   // → 400 REQUEST_REJECTED
        }
    }

    public static ResponseEntity<ApiEnvelope<RegistrationResponse>> toResponse(RegisterCustomerResult result) {
        return switch (result) {
            case Ready r -> ResponseEntity.status(r.created() ? 201 : 200)
                    .body(ApiEnvelope.success(new RegistrationResponse(r.requestId().value(),
                            r.customerId().value(), r.userName().value(), "READY")));
            case IdentityConflict c -> ApiEnvelope.failure(HttpStatus.CONFLICT, "IDENTITY_CONFLICT",
                    "The customer or user name is linked to another identity");
            case ProfileIncomplete p -> ApiEnvelope.failure(HttpStatus.CONFLICT, "CUSTOMER_PROFILE_INCOMPLETE",
                    "The customer profile does not allow account creation");
            case Unavailable u -> ApiEnvelope.failure(HttpStatus.SERVICE_UNAVAILABLE, "ACCOUNT_CREATION_UNAVAILABLE",
                    "Authentication account creation could not be completed");
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
| 2026-10-25 | Direct service calls between capabilities | the owning service exposes cohesive business operations through constructor injection and published commands/results; no cycles | calls through another capability's repository; forwarding interfaces; internal HTTP hops |
| 2026-10-25 | Role-only layer-first packages throughout | domain/application/web/persistence group by role; class names and contracts express business ownership; supersedes the earlier mixed capability/role layout | business subpackages in domain/application/web/persistence; a separate domain.shared package |
| 2026-10-25 | Cohesive service operations without required CQRS | an operation may read, validate, update and return data; the owning capability keeps its rules | mandatory Commands/Queries interfaces or a UseCase for every method |
| 2026-10-25 | Keys-only database | rules in code, UNIQUE for races only; schema stays simple to evolve | CHECK/FK constraints |
| 2026-10-25 | Server-side localized error messages, `vi` default + `en`, by `Accept-Language` | one source of truth for all channels; message catalogue reviewable per language | app-side localization; code-only responses |
