package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.core.password.PasswordLoginService;
import com.vpbank.dcp.core.session.TrustedDeviceSessions;
import com.vpbank.dcp.core.customer.CheckCustomerLoginEligibilityService;
import com.vpbank.dcp.core.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.core.password.PasswordVerifier;
import com.vpbank.dcp.core.password.PasswordProofReplay;
import com.vpbank.dcp.core.password.PasswordProofVerifier;
import com.vpbank.dcp.core.session.LoginSessionSecurityStore;
import com.vpbank.dcp.core.session.SessionAuthority;
import com.vpbank.dcp.core.session.SessionCryptography;
import com.vpbank.dcp.infrastructure.config.properties.CustomerLoginEligibilityProperties;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import tools.jackson.databind.json.JsonMapper;

class PasswordFlowConfigurationTest {

    @Test
    void defaultConfigurationRemainsClosed() {
        new WebApplicationContextRunner()
                .withUserConfiguration(PasswordFlowConfiguration.class)
                .withBean(JsonMapper.class, JsonMapper::new)
                .withBean(Clock.class, Clock::systemUTC)
                .withPropertyValues(
                        "auth.password-flow.customer-policy-version=test",
                        "auth.password-flow.credential-deadline-ms=1000",
                        "auth.password-flow.journey-deadline-ms=1000")
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean(PasswordLoginService.class));
    }

    @Test
    void explicitIntegrationFlagWiresThePasswordService() {
        new WebApplicationContextRunner()
                .withUserConfiguration(PasswordFlowConfiguration.class, PasswordIntegrationConfiguration.class)
                .withBean(JsonMapper.class, JsonMapper::new)
                .withBean(Clock.class, Clock::systemUTC)
                .withBean(LoginDeviceRepository.class, () -> mock(LoginDeviceRepository.class))
                .withBean(PasswordProofVerifier.class, () -> mock(PasswordProofVerifier.class))
                .withBean(PasswordProofReplay.class, () -> mock(PasswordProofReplay.class))
                .withBean(PasswordVerifier.class, () -> mock(PasswordVerifier.class))
                .withBean(CheckCustomerLoginEligibilityService.class,
                        () -> mock(CheckCustomerLoginEligibilityService.class))
                .withBean(CustomerOwnerRepository.class, () -> mock(CustomerOwnerRepository.class))
                .withBean(LoginSessionSecurityStore.class, () -> mock(LoginSessionSecurityStore.class))
                .withBean(SessionCryptography.class, () -> mock(SessionCryptography.class))
                .withBean(SessionAuthority.class, () -> mock(SessionAuthority.class))
                .withBean(TrustedDeviceSessions.class, () -> mock(TrustedDeviceSessions.class))
                .withBean(CustomerLoginEligibilityProperties.class,
                        () -> new CustomerLoginEligibilityProperties(30000))
                .withPropertyValues(
                        "spring.profiles.active=integration",
                        "auth.native-session.integration-activation-enabled=true",
                        "auth.customer.status-max-age-ms=30000",
                        "auth.password-flow.customer-policy-version=test",
                        "auth.password-flow.credential-deadline-ms=1000",
                        "auth.password-flow.journey-deadline-ms=900000")
                .run(context -> assertThat(context).hasNotFailed()
                        .hasSingleBean(PasswordLoginService.class));
    }

    @Test
    void activationFlagWithoutIntegrationProfileCannotExposeLoginService() {
        new WebApplicationContextRunner()
                .withUserConfiguration(PasswordFlowConfiguration.class, PasswordIntegrationConfiguration.class)
                .withBean(JsonMapper.class, JsonMapper::new)
                .withBean(Clock.class, Clock::systemUTC)
                .withPropertyValues(
                        "auth.native-session.integration-activation-enabled=true",
                        "auth.password-flow.customer-policy-version=test",
                        "auth.password-flow.credential-deadline-ms=1000",
                        "auth.password-flow.journey-deadline-ms=1000")
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean(PasswordLoginService.class));
    }
}
