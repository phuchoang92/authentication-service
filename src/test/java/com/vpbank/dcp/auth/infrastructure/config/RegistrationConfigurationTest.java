package com.vpbank.dcp.auth.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.auth.core.customer.CustomerRegistrationService;
import com.vpbank.dcp.auth.core.customer.RegistrationStore;
import com.vpbank.dcp.auth.infrastructure.adapter.in.web.registration.RegistrationController;
import java.time.Clock;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class RegistrationConfigurationTest {
    private static final String[] ENABLED = {
            "auth.registration.enabled=true",
            "auth.registration.request-digest-key-base64=" + Base64.getEncoder().encodeToString(new byte[32]),
            "auth.registration.customer.origin=https://customer.test",
            "auth.registration.keycloak.base-url=https://kc.test",
            "auth.registration.keycloak.realm=test",
            "auth.registration.keycloak.admin-client-id=auth-admin",
            "auth.registration.keycloak.admin-client-secret=secret",
            "auth.registration.notification.origin=https://notify.test",
            "auth.registration.notification.service-token=token"};

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withUserConfiguration(RegistrationConfiguration.class, RegistrationController.class)
            .withBean(RegistrationStore.class, () -> mock(RegistrationStore.class))
            .withBean(Clock.class, Clock::systemUTC);

    @Test
    void offByDefaultSoNoEndpointExists() {
        runner.run(context -> assertThat(context).hasNotFailed()
                .doesNotHaveBean(CustomerRegistrationService.class)
                .doesNotHaveBean(RegistrationController.class));
    }

    @Test
    void onWithEverySettingWiresTheEndpoint() {
        runner.withPropertyValues(ENABLED).run(context -> assertThat(context).hasNotFailed()
                .hasSingleBean(CustomerRegistrationService.class)
                .hasSingleBean(RegistrationController.class));
    }

    @Test
    void aShortDigestKeyStopsStartupNamingTheSetting() {
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.registration.request-digest-key-base64="
                        + Base64.getEncoder().encodeToString(new byte[8]))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("auth.registration.request-digest-key-base64");
                });
    }

    @Test
    void aMissingPartnerSettingStopsStartup() {
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.registration.notification.service-token=")
                .run(context -> assertThat(context).hasFailed());
    }
}
