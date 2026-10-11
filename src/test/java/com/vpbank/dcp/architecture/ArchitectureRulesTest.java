package com.vpbank.dcp.architecture;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tngtech.archunit.core.importer.ClassFileImporter;
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
            .that().resideInAPackage("..infrastructure.adapter.out..")
            .should().dependOnClassesThat().resideInAPackage("..infrastructure.adapter.in..")
            .because("outbound adapters do not depend on HTTP transport");

    @Test
    void productionCoreRemainsIndependent() {
        var classes = new ClassFileImporter().importPackages("com.vpbank.dcp.core");
        CORE_DOES_NOT_IMPORT_FRAMEWORK.check(classes);
        CORE_DOES_NOT_IMPORT_INFRASTRUCTURE.check(classes);
        OUTBOUND_ADAPTER_DOES_NOT_IMPORT_INBOUND_ADAPTER.check(
                new ClassFileImporter().importPackages("com.vpbank.dcp.infrastructure.adapter.out"));
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
