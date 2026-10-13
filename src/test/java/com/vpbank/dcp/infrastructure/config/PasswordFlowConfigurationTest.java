package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.application.password.PasswordLoginUnavailableService;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import tools.jackson.databind.json.JsonMapper;

class PasswordFlowConfigurationTest {

    @Test
    void currentConfigurationCannotWireTheRetiredPasswordFlow() {
        new WebApplicationContextRunner()
                .withUserConfiguration(PasswordFlowConfiguration.class)
                .withBean(JsonMapper.class, JsonMapper::new)
                .withBean(Clock.class, Clock::systemUTC)
                .withPropertyValues(
                        "auth.password-flow.command-key-id=test",
                        "auth.password-flow.command-hmac-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "auth.password-flow.customer-policy-version=test",
                        "auth.password-flow.customer-status-max-age-ms=1000",
                        "auth.password-flow.credential-deadline-ms=1000",
                        "auth.password-flow.journey-deadline-ms=1000")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(PasswordLoginUseCase.class);
                    assertThat(context.getBean(PasswordLoginUseCase.class))
                            .isInstanceOf(PasswordLoginUnavailableService.class);
                });
    }
}
