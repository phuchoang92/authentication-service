package com.vpbank.dcp.auth.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.Test;

/** The layer rules of ARCHITECTURE.md, checked on the production classes. */
class ArchitectureTest {
    private static final String ROOT = "com.vpbank.dcp.auth";
    /** Every capability package in core. A new capability is added here on purpose. */
    private static final String[] CAPABILITIES = {ROOT + ".core.customer.."};

    private final JavaClasses production = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages(ROOT);

    @Test
    void coreUsesOnlyTheJdkAndItself() {
        classes().that().resideInAPackage(ROOT + ".core..")
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "javax.crypto..",
                        ROOT + ".core..")
                .because("core holds the rules and knows no technology (the JDK's crypto is allowed)")
                .check(production);
    }

    @Test
    void coreHoldsOnlyCapabilityPackages() {
        classes().that().resideInAPackage(ROOT + ".core..")
                .should().resideInAnyPackage(CAPABILITIES)
                .because("core is grouped by capability, not by role")
                .check(production);
    }

    @Test
    void outboundAdaptersDoNotUseInboundAdapters() {
        noClasses().that().resideInAnyPackage(ROOT + ".infrastructure.adapter.out..",
                        ROOT + ".infrastructure.persistence..")
                .should().dependOnClassesThat().resideInAPackage(ROOT + ".infrastructure.adapter.in..")
                .check(production);
    }
}
