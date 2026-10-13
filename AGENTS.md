# Authentication Service

Read the workspace-root `AGENTS.md` and the documentation it requires before changing this source tree. Always read the active `architecture.md`, `code-conventions.md` and `code-design-rules-and-patterns.md` before changing code; do not rely on a previous turn's recollection. The G1 acceptance contract is in `docs/authentication-documentation/docs/design-v1/authentication-service-implementation-plan.md`.

This is the new `authentication-service` source tree, renamed from `authentication-service-rebuild` after the user removed the old project. Continue building from approved DD target contracts, not from any historical backup of the old source, tests, configuration or migrations. Use isolated test dependencies. The directory rename is not a deployment cutover; do not connect this build to running storage or deployment without a separate decision.

Core is JDK-only and owns ports. Infrastructure owns Spring, HTTP, JPA, Redis and JOSE. Apply RK01–RK12 to Redis key construction and authority operations. Report implemented and actually executed tests separately.

## Keycloak client authentication

The user-approved client configuration supports `CLIENT_SECRET_POST` (`client_id` and
`client_secret` in the HTTPS form) and `PRIVATE_KEY_JWT` (fresh ES256 client assertion).
This overrides older contracts that fixed the client to `authentication-service` and
required only `private_key_jwt`. Preserve that client ID and authentication method as
configuration defaults. Validate the selected credential at startup; never fall back to
another method on missing credentials or a provider rejection. The configured client ID
must also bind assertion issuer/subject and the pinned ID-token audience/authorized party.
Keep secrets out of output, use the existing bounded mTLS transport, and preserve ID-token
verification, failure mapping and the single-dispatch/no-retry behavior.

## Persistence conventions

The approved persistence refactor uses core `...Repository` ports and `Jpa...Adapter`
implementations, overriding the older Store naming examples in the shared design rules.
Persistence now uses the user-approved `infrastructure.persistence` root, grouped by
technical role: `adapter`, `repository`, `entity`, `projection`, `mapper` and `codec`.
Do not introduce customer/password/session subpackages in this persistence tree. Core
continues to organize ports/domain by capability. This layout overrides the older
persistence package examples in shared documentation. Custom EntityManager repositories
use `...PersistenceRepository`; Spring Data interfaces use `...JpaRepository`.
Do not introduce classes with the Reader suffix or aliases for the replaced SQL ports.

Adapters own transaction boundaries, lock order and multi-statement transitions.
Repositories only bind/execute SQL, extract typed database projections and check affected
rows. Handwritten stateless `...PersistenceMapper` classes restore domain/core result
values; adapters call them. Entities and projections contain database values only, with
no core object components or domain conversion methods. Preserve defensive byte copies,
content equality and redacted output. Existing core-typed write parameters remain allowed;
repositories must not construct core values or depend on adapters/mappers. Mappers perform
no I/O, clock access, transaction orchestration or freshness decisions.
The retired password-operation entity, Spring Data repository, EntityManager repository,
and SQL adapter have been removed. Do not recreate an operation write path merely to
store login failures. The public password endpoint currently returns a safe unavailable
result until a replacement login flow has an approved contract and tests. Guarded reads,
joins, locks and mutations for capabilities that still exist use focused EntityManager
repositories; never use a previously loaded entity for a decision after acquiring locks. No JPA caches,
relationships, cascades or generic base repository. Customer freshness belongs to the
JDK-only `CustomerFreshnessPolicy`; protected delivery serialization and digest checking
belong to `SessionDeliveryEscrowCodec`. Shared intent/escrow SQL belongs to
`SessionPersistenceRepository`; `JpaPasswordSessionAdapter` coordinates it with the
password-source repository in the same transaction. Keep password eligibility and
journey/operation transitions at that source boundary.

Preserve applied migration files and checksums. The user explicitly retired SQL
Authority Control: V9 removes `auth_authority_control`, and its lease port/adapter/repository
must not be restored. V11 retires the empty V1 login/device storage cluster; the old
password flow is disabled and must not be re-enabled against V11. Design and test its
replacement against the current customer/device tables first. Preserve Redis/BFF work
in progress and historical test reports; this does not authorize deployment, storage
cutover or Git push.
