package com.vpbank.dcp.architecture;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.lang.ArchRule;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAPackage;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAnyPackage;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

class ArchitectureRulesTest {

    private static final ArchRule CORE_DOES_NOT_IMPORT_FRAMEWORK = noClasses()
            .that().resideInAPackage("..core..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta.persistence..", "jakarta.servlet..",
                    "com.fasterxml.jackson..", "tools.jackson..", "com.nimbusds..",
                    "org.flywaydb..", "io.lettuce..", "redis.clients..", "com.vpbank.dcp.hpke..")
            .because("core owns policy and ports, while infrastructure owns technology");

    private static final ArchRule HPKE_LIBRARY_ONLY_IN_CRYPTO_ADAPTERS = noClasses()
            .that().resideInAPackage("com.vpbank.dcp..")
            .and().resideOutsideOfPackages("com.vpbank.dcp.hpke..", "..infrastructure.adapter.out.crypto..",
                    "..infrastructure.config..")
            .should().dependOnClassesThat().resideInAPackage("com.vpbank.dcp.hpke..")
            .because("only the crypto adapters and their wiring use the X-Wing library; core sees ports");

    private static final ArchRule CORE_DOES_NOT_IMPORT_INFRASTRUCTURE = noClasses()
            .that().resideInAPackage("..core..")
            .should().dependOnClassesThat().resideInAPackage("..infrastructure..")
            .because("dependency direction is infrastructure to core");

    /** ARCHITECTURE.md §4: each capability in {@code core/<capability>} imports only these. */
    private static final Map<String, Set<String>> CAPABILITY_IMPORTS = Map.of(
            "security", Set.of(),
            "replay", Set.of("security"),
            "customer", Set.of("security"),
            "device", Set.of("customer", "security"),
            "session", Set.of("customer", "device", "security"),
            "password", Set.of("session", "device", "customer", "replay", "security"),
            "trusteddevice", Set.of("session", "device", "customer", "replay", "security"));

    private static ArchRule capabilityImportsOnly(String capability, Set<String> allowed) {
        String[] permitted = Stream.concat(Stream.of(capability), allowed.stream())
                .map(name -> "..core." + name + "..").toArray(String[]::new);
        return noClasses().that().resideInAPackage("..core." + capability + "..")
                .should().dependOnClassesThat(resideInAPackage("..core..")
                        .and(DescribedPredicate.not(resideInAnyPackage(permitted))))
                .because("ARCHITECTURE.md §4 lets " + capability + " import only " + allowed);
    }

    private static final ArchRule OUTBOUND_ADAPTER_DOES_NOT_IMPORT_INBOUND_ADAPTER = noClasses()
            .that().resideInAnyPackage("..infrastructure.adapter.out..", "..infrastructure.persistence.adapter..")
            .should().dependOnClassesThat().resideInAPackage("..infrastructure.adapter.in..")
            .because("outbound adapters do not depend on HTTP transport");

    private static final String REPOSITORIES =
            "..infrastructure.persistence.repository..";

    private static final ArchRule APPLICATION_AND_CONTROLLER_USE_PORTS = noClasses()
            .that().resideInAnyPackage("..core.application..", "..infrastructure.adapter.in..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "..infrastructure.adapter.out..", "..infrastructure.persistence..");

    private static final ArchRule ADAPTERS_DO_NOT_EXECUTE_SQL = noClasses()
            .that().resideInAPackage("..infrastructure.persistence.adapter..")
            .should().dependOnClassesThat().haveFullyQualifiedName("jakarta.persistence.EntityManager");

    private static final ArchRule REPOSITORIES_DO_NOT_USE_COORDINATORS = noClasses()
            .that().resideInAPackage(REPOSITORIES)
            .should().dependOnClassesThat(new DescribedPredicate<>("coordinator or another adapter") {
                @Override
                public boolean test(com.tngtech.archunit.core.domain.JavaClass type) {
                    String pkg = type.getPackageName() + ".";
                    return pkg.contains(".core.application.") || pkg.contains(".infrastructure.config")
                            || pkg.contains(".adapter.in.")
                            || pkg.contains(".adapter.out.") || pkg.contains(".persistence.adapter.")
                            || pkg.contains(".persistence.mapper.");
                }
            });

    private static final ArchRule ENTITIES_STAY_IN_PERSISTENCE = noClasses()
            .that().resideOutsideOfPackage("..infrastructure.persistence..")
            .should().dependOnClassesThat().areAnnotatedWith(jakarta.persistence.Entity.class);

    private static final ArchRule PROJECTIONS_AND_ENTITIES_ARE_DATABASE_VALUES = noClasses()
            .that().resideInAnyPackage("..infrastructure.persistence.projection..",
                    "..infrastructure.persistence.entity..")
            .should().dependOnClassesThat().resideInAPackage("..core..");

    private static final ArchRule REPOSITORIES_DO_NOT_CONSTRUCT_CORE_VALUES = noClasses()
            .that().resideInAPackage(REPOSITORIES)
            .should().callConstructorWhere(new DescribedPredicate<>("core value constructor") {
                @Override
                public boolean test(com.tngtech.archunit.core.domain.JavaConstructorCall call) {
                    return call.getTargetOwner().getPackageName().contains(".core.");
                }
            });

    private static final ArchRule MAPPERS_ARE_PURE = noClasses()
            .that().resideInAPackage("..infrastructure.persistence.mapper..")
            .should().dependOnClassesThat(new DescribedPredicate<>("I/O, clock, framework or coordinator") {
                @Override
                public boolean test(com.tngtech.archunit.core.domain.JavaClass type) {
                    String pkg = type.getPackageName() + ".";
                    return pkg.startsWith("org.springframework") || pkg.startsWith("jakarta.persistence")
                            || pkg.startsWith("org.hibernate") || pkg.startsWith("java.sql")
                            || pkg.startsWith("java.net") || pkg.startsWith("java.io")
                            || pkg.startsWith("java.nio.file") || pkg.startsWith("tools.jackson")
                            || pkg.startsWith("com.fasterxml.jackson")
                            || type.getName().equals("java.time.Clock")
                            || pkg.contains(".core.application.") || pkg.contains(".infrastructure.config")
                            || pkg.contains(".adapter.") || pkg.contains(".persistence.repository.")
                            || type.getSimpleName().equals("SessionDeliveryEscrowCodec");
                }
            }).allowEmptyShould(true);

    @Test
    void persistenceResponsibilitiesRemainSeparated() {
        var production = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests())
                .withImportOption(new ImportOption.DoNotIncludeJars())
                .importPackages("com.vpbank.dcp");
        APPLICATION_AND_CONTROLLER_USE_PORTS.check(production);
        ADAPTERS_DO_NOT_EXECUTE_SQL.check(production);
        REPOSITORIES_DO_NOT_USE_COORDINATORS.check(production);
        ENTITIES_STAY_IN_PERSISTENCE.check(production);
        PROJECTIONS_AND_ENTITIES_ARE_DATABASE_VALUES.check(production);
        REPOSITORIES_DO_NOT_CONSTRUCT_CORE_VALUES.check(production);
        MAPPERS_ARE_PURE.check(production);
    }

    @Test
    void negativeFixturesDemonstratePersistenceViolationsAreCaught() {
        var fixtures = new ClassFileImporter().importPackages("com.vpbank.archfixtures");
        for (ArchRule rule : new ArchRule[]{APPLICATION_AND_CONTROLLER_USE_PORTS,
                ADAPTERS_DO_NOT_EXECUTE_SQL, REPOSITORIES_DO_NOT_USE_COORDINATORS,
                ENTITIES_STAY_IN_PERSISTENCE, PROJECTIONS_AND_ENTITIES_ARE_DATABASE_VALUES,
                REPOSITORIES_DO_NOT_CONSTRUCT_CORE_VALUES, MAPPERS_ARE_PURE}) {
            assertThat(catchThrowable(() -> rule.check(fixtures))).as(rule.getDescription())
                    .isInstanceOf(AssertionError.class);
        }
    }

    @Test
    void productionCoreRemainsIndependent() {
        var classes = new ClassFileImporter().importPackages("com.vpbank.dcp.core");
        CORE_DOES_NOT_IMPORT_FRAMEWORK.check(classes);
        CORE_DOES_NOT_IMPORT_INFRASTRUCTURE.check(classes);
        OUTBOUND_ADAPTER_DOES_NOT_IMPORT_INBOUND_ADAPTER.check(
                new ClassFileImporter().withImportOption(new ImportOption.DoNotIncludeTests())
                        .importPackages("com.vpbank.dcp.infrastructure"));
    }

    @Test
    void movedCapabilitiesImportOnlyDownstream() {
        var production = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests()).importPackages("com.vpbank.dcp.core");
        CAPABILITY_IMPORTS.forEach((capability, allowed) ->
                capabilityImportsOnly(capability, allowed).check(production));
    }

    @Test
    void coreHoldsOnlyCapabilityPackages() {
        var production = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests()).importPackages("com.vpbank.dcp.core");
        classes().should().resideInAnyPackage(CAPABILITY_IMPORTS.keySet().stream()
                        .map(name -> "com.vpbank.dcp.core." + name + "..").toArray(String[]::new))
                .because("ARCHITECTURE.md §2: no domain/application/port folders, only capabilities")
                .check(production);
    }

    @Test
    void negativeFixturesDemonstrateCapabilityDirectionViolationsAreCaught() {
        for (String capability : new String[]{"replay", "customer", "device", "session", "password", "trusteddevice"}) {
            var fixtures = new ClassFileImporter().importPackages("com.vpbank.archfixtures.core." + capability);
            assertThatThrownBy(() -> capabilityImportsOnly(capability, CAPABILITY_IMPORTS.get(capability))
                    .check(fixtures)).as(capability).isInstanceOf(AssertionError.class);
        }
    }

    @Test
    void cryptoLibraryStaysBehindTheCryptoAdapters() {
        var production = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests())
                .withImportOption(new ImportOption.DoNotIncludeJars())
                .importPackages("com.vpbank.dcp");
        HPKE_LIBRARY_ONLY_IN_CRYPTO_ADAPTERS.check(production);
    }

    @Test
    void negativeFixtureDemonstratesCryptoLibraryDependencyIsCaught() {
        var classes = new ClassFileImporter().importPackages("com.vpbank.dcp.archfixtures.core");
        assertThatThrownBy(() -> HPKE_LIBRARY_ONLY_IN_CRYPTO_ADAPTERS.check(classes))
                .isInstanceOf(AssertionError.class);
    }

    /** X-Wing runs on JDK 25 primitives; no Bouncy Castle may reach this service, not even transitively. */
    @Test
    void noBouncyCastleIsOnTheClasspath() {
        assertThat(getClass().getClassLoader().getResource("org/bouncycastle/crypto/digests/SHA3Digest.class"))
                .isNull();
    }

    @Test
    void negativeFixtureDemonstratesFrameworkDependencyIsCaught() {
        var classes = new ClassFileImporter().importPackages("com.vpbank.dcp.archfixtures.core");
        assertThatThrownBy(() -> CORE_DOES_NOT_IMPORT_FRAMEWORK.check(classes))
                .isInstanceOf(AssertionError.class);
    }

    @Test
    void negativeFixtureDemonstratesReverseInfrastructureDependencyIsCaught() {
        var classes = new ClassFileImporter().importPackages("com.vpbank.dcp.archfixtures.core");
        assertThatThrownBy(() -> CORE_DOES_NOT_IMPORT_INFRASTRUCTURE.check(classes))
                .isInstanceOf(AssertionError.class);
    }
}
