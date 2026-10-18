package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.application.password.PasswordLoginUnavailableService;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginRequestMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;

/**
 * Integration-only password composition. Production remains fail-closed.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(PasswordFlowProperties.class)
public class PasswordFlowConfiguration {

    @Bean
    PasswordLoginRequestMapper passwordLoginRequestMapper(PasswordFlowProperties policy,
                                                          JsonMapper json, Clock clock) {
        return new PasswordLoginRequestMapper(policy, json, clock);
    }

    @Bean
    PasswordLoginResponseMapper passwordLoginResponseMapper(Clock clock) {
        return new PasswordLoginResponseMapper(clock);
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
            havingValue = "false", matchIfMissing = true)
    PasswordLoginUseCase passwordLoginUseCase() {
        return new PasswordLoginUnavailableService();
    }

}
