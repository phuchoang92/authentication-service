package com.vpbank.dcp.architecture;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

class ArchitectureRulesTest {

    private static final ArchRule CORE_DOES_NOT_IMPORT_FRAMEWORK = noClasses()
            .that().resideInAPackage("..core..")
            .should().dependOnClassesThat().resideInAnyPackage(
                    "org.springframework..", "jakarta.persistence..", "jakarta.servlet..",
                    "com.fasterxml.jackson..", "tools.jackson..", "com.nimbusds..",
                    "org.flywaydb..", "io.lettuce..", "redis.clients..")
            .because("core owns policy and ports, while infrastructure owns technology");

    private static final ArchRule CORE_DOES_NOT_IMPORT_INFRASTRUCTURE = noClasses()
            .that().resideInAPackage("..core..")
            .should().dependOnClassesThat().resideInAPackage("..infrastructure..")
            .because("dependency direction is infrastructure to core");

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
                            || type.getSimpleName().equals("PasswordDeliveryEscrowCodec");
                }
            });

    @Test
    void persistenceResponsibilitiesRemainSeparated() {
        var production = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests())
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
                new ClassFileImporter().importPackages("com.vpbank.dcp.infrastructure"));
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
