package com.vpbank.dcp.auth.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.auth.application.port.in.RegisterCustomerUseCase;
import com.vpbank.dcp.auth.application.port.out.repository.RegistrationRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller.RegistrationController;
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
            .withUserConfiguration(RestConfiguration.class, RegistrationConfiguration.class, RegistrationController.class)
            .withBean(RegistrationRepository.class, () -> mock(RegistrationRepository.class));

    @Test
    void offByDefaultSoNoEndpointExists() {
        runner.run(context -> assertThat(context).hasNotFailed()
                .doesNotHaveBean(RegisterCustomerUseCase.class)
                .doesNotHaveBean(RegistrationController.class));
    }

    @Test
    void onWithEverySettingWiresTheEndpoint() {
        runner.withPropertyValues(ENABLED).run(context -> assertThat(context).hasNotFailed()
                .hasSingleBean(RegisterCustomerUseCase.class)
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
    void aZeroRequestLifetimeStopsStartupNamingTheSetting() {
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.registration.request-lifetime=PT0S")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("requestLifetime");
                });
    }

    @Test
    void aMissingPartnerSettingStopsStartup() {
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.registration.notification.service-token=")
                .run(context -> assertThat(context).hasFailed());
    }
}
