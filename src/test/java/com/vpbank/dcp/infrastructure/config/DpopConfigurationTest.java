package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.port.out.security.DpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidDpopConfigurationException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.NonProductionDpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.SpringDpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.config.properties.DpopProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class DpopConfigurationTest {
    private final WebApplicationContextRunner context = new WebApplicationContextRunner()
            .withUserConfiguration(DpopConfiguration.class)
            .withBean(Sha256Digests.class, Sha256Digests::new)
            .withBean(StrictJoseJson.class, StrictJoseJson::new);

    @Test
    void defaultsEnableVerificationWithEs256EvenWithoutAProfile() {
        context.run(started -> {
            assertThat(started).hasNotFailed().hasSingleBean(DpopProofDecoder.class);
            assertThat(started.getBean(DpopProofDecoder.class)).isInstanceOf(SpringDpopProofDecoder.class);
            assertThat(started.getBean(DpopProperties.class).enabled()).isTrue();
            assertThat(started.getBean(DpopProperties.class).allowedAlgorithms()).containsExactly("ES256");
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"local", "dev", "test", "qa", "uat", "staging", "integration", "non-prod"})
    void disablingRequiresAnExplicitNonProductionProfile(String profile) {
        context.withInitializer(started -> started.getEnvironment().setActiveProfiles(profile))
                .withPropertyValues("auth.dpop.enabled=false").run(started -> {
                    assertThat(started).hasNotFailed();
                    assertThat(started.getBean(DpopProofDecoder.class))
                            .isInstanceOf(NonProductionDpopProofDecoder.class);
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "prod", "production", "dev,prod", "integration,production", "unknown", "dev,unknown"})
    void disablingFailsWithoutAProfileOrWithAnyProductionOrUnknownProfile(String profiles) {
        context.withInitializer(started -> started.getEnvironment().setActiveProfiles(
                        profiles.isEmpty() ? new String[0] : profiles.split(",")))
                .withPropertyValues("auth.dpop.enabled=false").run(started -> {
                    assertThat(started).hasFailed();
                    assertThat(started.getStartupFailure()).hasRootCauseInstanceOf(InvalidDpopConfigurationException.class);
                });
    }

    @Test
    void bindsAnExplicitAllowlistAndPermitsEnabledProduction() {
        context.withInitializer(started -> started.getEnvironment().setActiveProfiles("prod"))
                .withPropertyValues("auth.dpop.allowed-algorithms=ES384,PS256")
                .run(started -> {
                    assertThat(started).hasNotFailed();
                    assertThat(started.getBean(DpopProperties.class).allowedAlgorithms())
                            .containsExactlyInAnyOrder("ES384", "PS256");
                });
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "none", "HS256", "EdDSA", "ES256,UNKNOWN"})
    void emptyUnsupportedAndSymmetricAlgorithmsFailStartup(String algorithms) {
        context.withPropertyValues("auth.dpop.allowed-algorithms=" + algorithms)
                .run(started -> assertThat(started).hasFailed());
    }
}
