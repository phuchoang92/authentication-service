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
    private static final String DOMAIN = ROOT + ".domain..";
    private static final String APPLICATION = ROOT + ".application..";
    private static final String COMMAND = ROOT + ".application.command";
    private static final String RESULT = ROOT + ".application.result";
    private static final String PORT_IN = ROOT + ".application.port.in";
    private static final String PORT_OUT = ROOT + ".application.port.out..";
    private static final String SERVICE = ROOT + ".application.service";
    private static final String INFRA = ROOT + ".infrastructure..";
    private static final String REST = ROOT + ".infrastructure.adapter.in.rest";
    private static final String OUT = ROOT + ".infrastructure.adapter.out";
    private static final String CONFIG = ROOT + ".infrastructure.config";

    private final JavaClasses production = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages(ROOT);

    @Test
    void ringsDependInwardOnly() {
        Architectures.onionArchitecture()
                .domainModels(DOMAIN)
                .applicationServices(APPLICATION)
                .adapter("rest", REST + "..")
                .adapter("persistence", OUT + ".persistence..")
                .adapter("customer", OUT + ".customer..")
                .adapter("keycloak", OUT + ".keycloak..")
                .adapter("notification", OUT + ".notification..")
                .adapter("valkey", OUT + ".valkey..")
                .adapter("jose", OUT + ".jose..")
                .adapter("captcha", OUT + ".captcha..")
                .withOptionalLayers(true)
                // config wires every ring; it is the only package allowed to see all of them
                .ignoreDependency(JavaClass.Predicates.resideInAPackage(CONFIG + ".."), DescribedPredicate.alwaysTrue())
                .check(production);
    }

    @Test
    void domainKnowsOnlyTheJdkLombokAndItself() {
        classes().that().resideInAPackage(DOMAIN)
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "lombok..", DOMAIN)
                .because("domain holds the rules and knows no technology")
                .check(production);
    }

    @Test
    void applicationKnowsOnlyDomainAndItselfNeverInfrastructure() {
        classes().that().resideInAPackage(APPLICATION)
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "javax.crypto..", "lombok..", DOMAIN, APPLICATION)
                .because("use cases drive ports; adapters, Spring and framework properties stay outside")
                .check(production);
        noClasses().that().resideInAnyPackage(DOMAIN, APPLICATION)
                .should().dependOnClassesThat().resideInAPackage(INFRA)
                .because("infrastructure groups adapters and config; core never imports it")
                .check(production);
    }

    @Test
    void ringsHoldOnlyRolePackages() {
        onlyPackages(DOMAIN, ROOT + ".domain.model", ROOT + ".domain.exception");
        onlyPackages(APPLICATION, COMMAND, RESULT, PORT_IN, ROOT + ".application.port.out.repository",
                ROOT + ".application.port.out.gateway", ROOT + ".application.port.out.model",
                ROOT + ".application.port.out.exception", SERVICE);
        onlyPackages(REST + "..", REST + ".common", REST + ".controller", REST + ".dto.request", REST + ".dto.response",
                REST + ".mapper");
        onlyPackages(OUT + ".persistence..", OUT + ".persistence.common", OUT + ".persistence.adapter",
                OUT + ".persistence.entity", OUT + ".persistence.repository", OUT + ".persistence.mapper");
        // everything outside the core rings sits under infrastructure (plus the Boot entry point)
        classes().that().resideOutsideOfPackages(DOMAIN, APPLICATION, INFRA)
                .should().haveSimpleName("AuthenticationApplication")
                .because("adapters and config live under infrastructure")
                .check(production);
    }

    @Test
    void inboundContractsAreSplitIntoUseCasesCommandsAndResults() {
        classes().that().resideInAPackage(PORT_IN).should().beInterfaces()
                .andShould().haveSimpleNameEndingWith("UseCase")
                .because("application.port.in holds inbound interfaces only")
                .check(production);
        classes().that().resideInAPackage(COMMAND).and().areTopLevelClasses().should().haveSimpleNameEndingWith("Command")
                .orShould().haveSimpleNameEndingWith("Solution")
                .because("commands and their input values live in application.command")
                .check(production);
        classes().that().resideInAPackage(RESULT).and().areTopLevelClasses().should().haveSimpleNameEndingWith("Result")
                .orShould().haveSimpleNameEndingWith("Challenge").orShould().haveSimpleNameEndingWith("Summary")
                .because("results and their output values live in application.result")
                .check(production);
        noClasses().that().resideInAnyPackage(COMMAND, RESULT, PORT_IN)
                .should().dependOnClassesThat().resideInAnyPackage(SERVICE, PORT_OUT)
                .because("published contracts do not expose services or outbound ports")
                .check(production);
    }

    @Test
    void outboundPortsAreGroupedByRoleAndIndependentOfInboundContracts() {
        classes().that().resideInAPackage(ROOT + ".application.port.out.repository")
                .should().beInterfaces().orShould().beNestedClasses()
                .andShould().haveSimpleNameEndingWith("Repository").orShould().haveSimpleNameEndingWith("Store")
                .orShould().beNestedClasses()
                .check(production);
        classes().that().resideInAPackage(ROOT + ".application.port.out.gateway").and().areTopLevelClasses()
                .should().beInterfaces()
                .because("gateways are capability interfaces an adapter implements")
                .check(production);
        classes().that().resideInAPackage(ROOT + ".application.port.out.exception")
                .should().beAssignableTo(RuntimeException.class).andShould().haveSimpleNameEndingWith("Exception")
                .check(production);
        classes().that().resideInAPackage(ROOT + ".application.port.out.model").and().areTopLevelClasses()
                .should().beRecords()
                .because("outbound models are immutable application-owned contracts")
                .check(production);
        noClasses().that().resideInAPackage(PORT_OUT)
                .should().dependOnClassesThat().resideInAnyPackage(COMMAND, RESULT, PORT_IN, SERVICE)
                .because("outbound contracts describe a dependency step, never the application operation")
                .check(production);
    }

    @Test
    void servicesHaveNoCycles() {
        SlicesRuleDefinition.slices().assignedFrom(new SliceAssignment() {
                    @Override
                    public SliceIdentifier getIdentifierOf(JavaClass javaClass) {
                        return javaClass.getPackageName().equals(SERVICE)
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
    void controllersAndRestMappersAreGlue() {
        classes().that().resideInAPackage(REST + ".controller")
                .should().onlyDependOnClassesThat().resideInAnyPackage("java..", "jakarta.validation..", "lombok..",
                        "org.springframework..", PORT_IN, COMMAND, RESULT, REST + "..")
                .because("a controller maps in, calls the use case and maps out; it decides nothing")
                .check(production);
        noClasses().that().resideInAnyPackage(REST + ".controller", REST + ".mapper")
                .should().dependOnClassesThat().resideInAnyPackage(SERVICE, PORT_OUT)
                .because("REST never reaches services or outbound ports")
                .check(production);
    }

    @Test
    void namesSayWhereAClassLives() {
        classes().that().haveSimpleNameEndingWith("Request").or().haveSimpleNameEndingWith("Response")
                .and().resideInAPackage(REST + "..")
                .should().resideInAPackage("..dto..").check(production);
        classes().that().haveSimpleNameEndingWith("Mapper")
                .should().resideInAPackage("..mapper..").andShould().haveModifier(JavaModifier.FINAL)
                .check(production);
        classes().that().haveSimpleNameEndingWith("RestMapper").should().resideInAPackage(REST + ".mapper").check(production);
        noClasses().should().haveSimpleNameEndingWith("WebMapper").check(production);
        classes().that().areAnnotatedWith("jakarta.persistence.Entity")
                .should().resideInAPackage(OUT + ".persistence.entity")
                .andShould().haveSimpleNameEndingWith("Entity")
                .check(production);
        classes().that().haveSimpleNameEndingWith("UseCase").should().resideInAPackage(PORT_IN).check(production);
        classes().that().haveSimpleNameEndingWith("Port").should().resideInAPackage(ROOT + ".application.port.out.gateway")
                .check(production);
        classes().that().haveSimpleNameEndingWith("Controller").should().resideInAPackage(REST + ".controller").check(production);
        classes().that().haveSimpleNameEndingWith("Service").should().resideInAPackage(SERVICE).check(production);
        classes().that().haveSimpleNameEndingWith("Filter").should().resideInAPackage(REST + ".common").check(production);
        classes().that().haveSimpleNameEndingWith("Configuration").or().haveSimpleNameEndingWith("Properties")
                .should().resideInAPackage(CONFIG).check(production);
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
                .should().resideInAnyPackage(OUT + ".persistence.entity", OUT + ".persistence.common", OUT + "..dto")
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
