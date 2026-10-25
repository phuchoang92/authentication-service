# Architecture — authentication-service

**Status:** approved layout, 2026-10-24. This file is the single source for **layers, packages
and dependency direction**. `CLAUDE.md` keeps the code-level rules (records, results, names,
exceptions). DD target contracts (API, security, data, Redis) still win over both.

**Goal:** a newcomer can trace one endpoint from controller to MySQL/Valkey/HTTP by opening a
few files in two folders: `core/<capability>/` and the adapters for it. Hexagonal here means
one thing: **core holds the rules and knows nothing about technology; adapters translate.**
Nothing else is added unless a rule below asks for it.

## 1. Layers

```text
com.vpbank.dcp
├── AuthenticationApplication.java          startup only
├── core/<capability>/                      JDK only: rules of one capability
└── infrastructure/
    ├── adapter/in/web/<capability>/        HTTP in: controller + request/response DTOs
    ├── adapter/in/web/security/            mTLS principal, DPoP filter, security error writer
    ├── adapter/in/web/error/               ApiError + ApiErrorHandler
    ├── adapter/out/<technology>/           redis, keycloak, mfa, customer, crypto, http
    ├── persistence/                        MySQL: adapter, repository, entity, projection, mapper, codec
    └── config/                             wiring + properties/ (validated settings)
```

| Layer | Holds | May import | Must not import or do |
|---|---|---|---|
| **Core** `core/<capability>` | service class, its ports, commands, results, domain values | JDK; other capabilities downstream of it (§4) | Spring, Jackson, JPA, Redis, Nimbus/JOSE, anything in `infrastructure` |
| **Inbound web** `adapter/in/web/<capability>` | controller, DTOs, wire parsing, HTTP status and headers | core services and their values; `web/error` | outbound adapters, persistence, config; business decisions |
| **Outbound** `adapter/out/<technology>` | one implementation per core port, for one technology | core ports and values; its own library; `adapter/out/http` for transport | inbound adapters; core services; another technology's internals |
| **Persistence** `persistence/` | `Jpa…Adapter` (transaction), `…PersistenceRepository` (SQL), entity, projection, mapper, codec | core ports and values; JPA | business decisions; HTTP; Valkey (rules in `AGENTS.md` § Persistence) |
| **Config** `config/` | `@Configuration` beans, `@ConfigurationProperties`, startup checks | everything, to wire it | business logic; deciding outcomes |

Direction is always **adapter → core**. Core never calls an adapter except through a port it owns.

## 2. Inside one core capability

Everything about a capability sits **flat** in `core/<capability>/`. No `domain`, `application`,
`port`, `model` or `dto` subfolders.

| Kind | Exists when | Name |
|---|---|---|
| **Service** | always; it is the use case | `<Verb><Noun>Service` or `<Capability>Service`, e.g. `ExtendSessionService` |
| **Port** (interface) | core needs something outside core: MySQL, Valkey, an HTTP partner, JOSE/Nimbus | what it does: `SessionActivityStore`, `CustomerDirectory`, `PasswordVerifier` |
| **Command / Result** | input/output of a service method; result is sealed when outcomes lead to different behavior | `…Command`, `…Result` |
| **Domain value** | it has an invariant, or prevents a mix-up the compiler can catch | the business noun: `SessionDeadlines`, `SubjectId` |
| **Policy** | pure decision logic of 20+ lines used by the service | `…Policy` |
| **Exception** | someone `catch`es it or maps it separately (usually a port's "unavailable") | `…UnavailableException` |

**Not allowed** (this is what made the code large):

- an inbound `*UseCase` interface in front of a service: the controller calls the class;
- an interface with one implementation inside core;
- a class whose logic is under 20 lines: write it as a method;
- a record that only wraps another record on its way to the next layer;
- a `shared`/`common`/`util` package: a value lives in the capability that owns its meaning;
- an exception nobody distinguishes: use the JDK exceptions.

A service may grow to 200 lines or 5 collaborators. Split it only past that, or when a second
reason to change is **observed**, not predicted.

## 3. Capabilities

| Capability | Owns | Ports it defines (implemented in) |
|---|---|---|
| `security` | `Digest32`, `RequestKeyThumbprint`, DPoP proof values | `DpopProofDecoder` (crypto) |
| `customer` | `SubjectId`, `CustomerNumber`, status, owner and eligibility rules | `CustomerDirectory` (customer HTTP), `CustomerOwnerRepository` (persistence) |
| `device` | `BindingId`, trusted device, `StoredDeviceKey`, revocation | `LoginDeviceRepository`, `DeviceRevocationRepository` (persistence) |
| `replay` | one-time proof and assertion markers | `ReplayProtection`, `AssertionReplay` (redis) |
| `session` | ACTIVE and restricted sessions: issue, find, extend, consume; `SessionDeadlines` | `SessionAuthority`, `SessionActivityStore`, `RestrictedSessionStore` (redis), `SessionCryptography`, `RestrictedSessionCryptography` (crypto), `LoginSessionSecurityStore` (persistence) |
| `password` | password login | `PasswordVerifier` (keycloak), `PasswordProofVerifier` (crypto), `PasswordProofReplay` (redis) |
| `trusteddevice` | init / verify / confirm of a new or known device | `MfaTransactions` (mfa), `TrustedDeviceRecords` (persistence), `BffCallerAssertions`, `ServerKeyExchange` (crypto) |

A port lives in the capability that **uses** it: MFA in `trusteddevice`, the Keycloak verifier in
`password`. Today's `credential` and `mfa` packages are not capabilities; they fold into
`password` and `trusteddevice`.

## 4. Dependency direction

```text
            password        trusteddevice        (entry capabilities: one per endpoint group)
               │  \            /  │
               │   └──> session <─┘
               │          │  │
               ├──> device ─┤  │
               │          │ ┌┘
               ├──> customer
               ├──> replay
               └──> security <── (everyone)
```

Allowed imports, top to bottom only:

| From | May import |
|---|---|
| `password` | `session`, `device`, `customer`, `replay`, `security` |
| `trusteddevice` | `session`, `device`, `customer`, `replay`, `security` |
| `session` | `device`, `customer`, `security` |
| `device` | `customer`, `security` |
| `customer` | `security` |
| `replay` | `security` |
| `security` | nothing |

`password` and `trusteddevice` never import each other. When both need something, it moves
down into `session`, `device` or `customer`.

**Violations:** none. The three cycles found on 2026-10-25 (`device` → `password`,
`trusteddevice` → `password` via `StoredDeviceKey`; `password` → `trusteddevice` via
restricted-session issuance) were removed by slices 3 and 4. ArchUnit
`movedCapabilitiesImportOnlyDownstream` enforces this table, and `coreHoldsOnlyCapabilityPackages`
rejects any class in core outside these seven packages.

## 5. Adapters

- **Controller:** parses the wire, calls one service method, and maps the result to status +
  body + headers in a `switch` over the sealed result. Mapping stays in the controller unless
  it exceeds 20 lines; then it becomes one `…ResponseMapper` per controller. DTOs are records
  in `dto/` beside it.
- **Outbound adapter:** implements one port. It translates vendor errors into the port's
  result or its one `…UnavailableException`; core never catches a vendor exception. Key and
  URL building stay inside the adapter (`redis/key`, endpoint constants).
- **Persistence:** keeps the approved roles in `AGENTS.md` § Persistence conventions. The
  adapter owns the transaction, the repository runs SQL, and the mapper restores core values.
- **Config:** one `<Capability>Configuration` per capability, carrying the same profile/flag
  gate as its controller. Properties are records with Bean Validation. Cross-setting checks
  throw `IllegalStateException` naming the setting.

## 6. What "clean" is measured by

| Check | Command | Baseline (2026-10-25) | Target | After slices 1–6 (2026-10-25) |
|---|---|---|---|---|
| Core is JDK-only, adapters don't cross | `./mvnw -B verify` (ArchUnit) | passes | passes | passes |
| Capability direction (§4) | ArchUnit `movedCapabilitiesImportOnlyDownstream` | 3 violations | 0 | **0** |
| Old role folders in core | `ls src/main/java/com/vpbank/dcp/core` | `application domain port session` | capability names only | **7 capabilities only** |
| Inbound `*UseCase` interfaces | `python3 tools/code-metrics.py ports` | 4 | 0 | **0** |
| Exceptions nobody distinguishes | `python3 tools/code-metrics.py exceptions` | 29 | 0 | 18 (0 in core; 18 in infrastructure) |
| Core records > 6 parts or 2 booleans side by side | `python3 tools/code-metrics.py records` | 7 | 0, or a reason written on the type | 3, each 7 parts with the reason written on the type (record cleanup, 2026-10-25) |
| Types opened to trace an endpoint | `python3 tools/code-metrics.py trace` | password 191, trusted device 172 | drops every slice; extend ≈ 10 | password 181, trusted device 168 (after record cleanup; +3/+4 from named groups) |
| Files in `src/main` | `python3 tools/code-metrics.py` | 338 | drops, never rises without new behavior | 323 |

A slice is done only when no number in this table gets worse.

## 7. Moving there: one capability per slice

**Done 2026-10-25:** all six slices below are applied. Remaining work is the records and
infrastructure exceptions in §6, done with the same checklist.

Order used, bottom of §4 first, so each slice only imported capabilities already moved:

1. **security + replay:** shared values, `DpopProofDecoder`, replay ports.
2. **customer:** remove `CheckCustomerLoginEligibilityUseCase`.
3. **device:** move `StoredDeviceKey` here (removes two cycles).
4. **session:** merge `domain/session`, `application/session`, `port/*/session` into `core/session`; move restricted-session issuance from `trusteddevice`; remove `IssueLoginSessionUseCase`.
5. **password:** fold in `credential`; remove `PasswordLoginUseCase`; no `trusteddevice` imports.
6. **trusteddevice:** fold in `mfa`; remove `TrustedDeviceUseCase`.

Checklist for every slice:

- [ ] Types moved into `core/<capability>/`, flat; nothing left in the old folders for it.
- [ ] Records that only wrapped another record are merged; one-implementation core interfaces removed.
- [ ] Exceptions nobody catches replaced by JDK exceptions.
- [ ] ArchUnit rules tied to old package names rewritten as §4 direction rules.
- [ ] No wire, Redis key, SQL, signing or migration change (DD target contracts unchanged).
- [ ] `./mvnw -B verify` green; §6 numbers no worse; executed test counts reported.
