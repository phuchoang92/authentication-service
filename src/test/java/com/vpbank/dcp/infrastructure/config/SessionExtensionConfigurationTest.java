package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.core.session.ExtendSessionService;
import com.vpbank.dcp.core.session.SessionActivityStore;
import com.vpbank.dcp.infrastructure.adapter.in.web.session.SessionExtensionController;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisSessionActivityStore;
import com.vpbank.dcp.infrastructure.config.properties.IngressProperties;
import java.time.Clock;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

class SessionExtensionConfigurationTest {
    private static final String BFF = "spiffe://bank/mobile-bff";
    private static final String[] ACTIVE = {
            "spring.profiles.active=integration",
            "auth.native-session.integration-activation-enabled=true",
            "auth.session-extension.bff-workload-uri=" + BFF,
            "auth.session-extension.activity-routes=accounts.read,transfers.create",
            "auth.session-extension.max-admission-age-ms=30000",
            "auth.session-extension.max-clock-skew-ms=2000"};

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withUserConfiguration(SessionExtensionConfiguration.class, SessionExtensionController.class)
            .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
            .withBean(RedisServerIdentity.class, () -> mock(RedisServerIdentity.class))
            .withBean(Clock.class, Clock::systemUTC)
            .withBean(IngressProperties.class,
                    () -> new IngressProperties("https://bank.test", Set.of(BFF, "spiffe://bank/other")));

    @Test
    void integrationActivationAssemblesTheEndpoint() {
        runner.withPropertyValues(ACTIVE).run(started -> {
            assertThat(started).hasNotFailed()
                    .hasSingleBean(ExtendSessionService.class)
                    .hasSingleBean(SessionExtensionController.class);
            assertThat(started.getBean(SessionActivityStore.class))
                    .isInstanceOf(RedisSessionActivityStore.class);
        });
    }

    @Test
    void withoutTheActivationFlagNothingIsExposed() {
        runner.withPropertyValues("spring.profiles.active=integration").run(started ->
                assertThat(started).hasNotFailed()
                        .doesNotHaveBean(ExtendSessionService.class)
                        .doesNotHaveBean(SessionExtensionController.class));
    }

    @Test
    void withoutTheIntegrationProfileNothingIsExposed() {
        runner.withPropertyValues("auth.native-session.integration-activation-enabled=true").run(started ->
                assertThat(started).hasNotFailed()
                        .doesNotHaveBean(ExtendSessionService.class)
                        .doesNotHaveBean(SessionExtensionController.class));
    }

    @Test
    void bffMustBeAnAllowedWorkload() {
        runner.withPropertyValues(ACTIVE)
                .withPropertyValues("auth.session-extension.bff-workload-uri=spiffe://bank/unknown")
                .run(started -> {
                    assertThat(started).hasFailed();
                    assertThat(started.getStartupFailure()).rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("auth.session-extension.bff-workload-uri");
                });
    }

    @Test
    void missingRoutePolicyFailsStartup() {
        runner.withPropertyValues(ACTIVE)
                .withPropertyValues("auth.session-extension.activity-routes=")
                .run(started -> assertThat(started).hasFailed());
    }
}
