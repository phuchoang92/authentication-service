package com.vpbank.dcp.auth.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.library.Architectures;
import com.tngtech.archunit.library.dependencies.SliceAssignment;
import com.tngtech.archunit.library.dependencies.SliceIdentifier;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;
import org.junit.jupiter.api.Test;

/** The [arch] rules of ARCHITECTURE.md, checked on the production classes. */
class ArchitectureTest {
    private static final String ROOT = "com.vpbank.dcp.auth";

    private final JavaClasses production = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages(ROOT);

    @Test
    void ringsDependInwardOnly() {
        Architectures.onionArchitecture()
                .domainModels(ROOT + ".domain..")
                .applicationServices(ROOT + ".application..")
                .adapter("web", ROOT + ".adapter.in.web..")
                .adapter("persistence", ROOT + ".adapter.out.persistence..")
                .adapter("customer", ROOT + ".adapter.out.customer..")
                .adapter("keycloak", ROOT + ".adapter.out.keycloak..")
                .adapter("notification", ROOT + ".adapter.out.notification..")
                .adapter("valkey", ROOT + ".adapter.out.valkey..")
                .adapter("jose", ROOT + ".adapter.out.jose..")
                .adapter("captcha", ROOT + ".adapter.out.captcha..")
                .withOptionalLayers(true)
                // config wires every ring; it is the only package allowed to see all of them
                .ignoreDependency(JavaClass.Predicates.resideInAPackage(ROOT + ".config.."),
                        DescribedPredicate.alwaysTrue())
                .check(production);
    }

    @Test
    void domainKnowsOnlyTheJdkLombokAndItself() {
        classes().that().resideInAPackage(ROOT + ".domain..")
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "lombok..", ROOT + ".domain..")
                .because("domain holds the rules and knows no technology")
                .check(production);
    }

    @Test
    void applicationKnowsOnlyDomainAndItself() {
        classes().that().resideInAPackage(ROOT + ".application..")
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "javax.crypto..", "lombok..",
                        ROOT + ".domain..", ROOT + ".application..")
                .because("use cases drive ports; adapters, Spring and framework properties stay outside")
                .check(production);
    }

    @Test
    void ringsHoldOnlyRolePackages() {
        onlyPackages(ROOT + ".domain..", ROOT + ".domain.model", ROOT + ".domain.exception");
        onlyPackages(ROOT + ".application..", ROOT + ".application.port.in", ROOT + ".application.port.out",
                ROOT + ".application.service");
        onlyPackages(ROOT + ".adapter.in.web..", ROOT + ".adapter.in.web.common", ROOT + ".adapter.in.web.controller",
                ROOT + ".adapter.in.web.dto.request", ROOT + ".adapter.in.web.dto.response", ROOT + ".adapter.in.web.mapper");
        onlyPackages(ROOT + ".adapter.out.persistence..", ROOT + ".adapter.out.persistence.common",
                ROOT + ".adapter.out.persistence.adapter", ROOT + ".adapter.out.persistence.entity",
                ROOT + ".adapter.out.persistence.repository", ROOT + ".adapter.out.persistence.mapper");
    }

    @Test
    void servicesHaveNoCycles() {
        SlicesRuleDefinition.slices().assignedFrom(new SliceAssignment() {
                    @Override
                    public SliceIdentifier getIdentifierOf(JavaClass javaClass) {
                        return javaClass.getPackageName().equals(ROOT + ".application.service")
                                ? SliceIdentifier.of(javaClass.getSimpleName()) : SliceIdentifier.ignore();
                    }

                    @Override
                    public String getDescription() {
                        return "one slice per application service class";
                    }
                })
                .should().beFreeOfCycles()
                .because("if Login calls Trusted Device, Trusted Device must not call Login back")
                .check(production);
    }

    @Test
    void controllersAreGlue() {
        classes().that().resideInAPackage(ROOT + ".adapter.in.web.controller")
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "jakarta.validation..", "lombok..",
                        "org.springframework..", ROOT + ".application.port.in", ROOT + ".adapter.in.web..")
                .because("a controller maps in, calls the use case and maps out; it decides nothing")
                .check(production);
    }

    @Test
    void namesSayWhereAClassLives() {
        classes().that().haveSimpleNameEndingWith("Request").or().haveSimpleNameEndingWith("Response")
                .and().resideInAPackage(ROOT + ".adapter.in..")
                .should().resideInAPackage("..dto..").check(production);
        classes().that().haveSimpleNameEndingWith("Mapper")
                .should().resideInAPackage("..mapper..").andShould().haveModifier(JavaModifier.FINAL)
                .check(production);
        classes().that().areAnnotatedWith("jakarta.persistence.Entity")
                .should().resideInAPackage(ROOT + ".adapter.out.persistence.entity")
                .andShould().haveSimpleNameEndingWith("Entity")
                .check(production);
        classes().that().haveSimpleNameEndingWith("UseCase")
                .should().resideInAPackage(ROOT + ".application.port.in").check(production);
        classes().that().haveSimpleNameEndingWith("Port")
                .should().resideInAPackage(ROOT + ".application.port.out").check(production);
        classes().that().haveSimpleNameEndingWith("Controller")
                .should().resideInAPackage(ROOT + ".adapter.in.web.controller").check(production);
        classes().that().haveSimpleNameEndingWith("Service")
                .should().resideInAPackage(ROOT + ".application.service").check(production);
        classes().that().haveSimpleNameEndingWith("Filter")
                .should().resideInAPackage(ROOT + ".adapter.in.web.common").check(production);
    }

    @Test
    void lombokStaysOnTheAllowList() {
        noClasses().should().beAnnotatedWith("lombok.Data")
                .orShould().beAnnotatedWith("lombok.Setter")
                .orShould().beAnnotatedWith("lombok.EqualsAndHashCode")
                .orShould().beAnnotatedWith("lombok.ToString")
                .orShould().beAnnotatedWith("lombok.Value")
                .because("entities keep named state changes and explicit identity; records already print and compare")
                .check(production);
        classes().that().areAnnotatedWith("lombok.AllArgsConstructor").or().areAnnotatedWith("lombok.Getter")
                .should().resideInAnyPackage(ROOT + ".adapter.out.persistence.entity", ROOT + ".adapter.out..dto")
                .allowEmptyShould(true)
                .because("all-args constructors and getters are for JPA entities and partner DTOs only")
                .check(production);
    }

    private void onlyPackages(String ring, String... allowed) {
        classes().that().resideInAPackage(ring)
                .should().resideInAnyPackage(allowed)
                .because("rings are grouped by role; a capability is a class name, not a package")
                .check(production);
    }
}
