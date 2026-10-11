# Authentication Service

Read the workspace-root `AGENTS.md` and the documentation it requires before changing this source tree. Always read the active `architecture.md`, `code-conventions.md` and `code-design-rules-and-patterns.md` before changing code; do not rely on a previous turn's recollection. The G1 acceptance contract is in `docs/authentication-documentation/docs/design-v1/authentication-service-implementation-plan.md`.

This is the new `authentication-service` source tree, renamed from `authentication-service-rebuild` after the user removed the old project. Continue building from approved DD target contracts, not from any historical backup of the old source, tests, configuration or migrations. Use isolated test dependencies. The directory rename is not a deployment cutover; do not connect this build to running storage or deployment without a separate decision.

Core is JDK-only and owns ports. Infrastructure owns Spring, HTTP, JPA, Redis and JOSE. Apply RK01–RK12 to Redis key construction and authority operations. Report implemented and actually executed tests separately.
