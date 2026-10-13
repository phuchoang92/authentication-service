package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.application.customer.CheckCustomerLoginEligibilityService;
import com.vpbank.dcp.core.port.in.customer.CheckCustomerLoginEligibilityUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.infrastructure.config.properties.CustomerLoginEligibilityProperties;
import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Assembles Customer login policy independently of the authentication method. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(CustomerLoginEligibilityProperties.class)
public class CustomerLoginConfiguration {
    @Bean
    CheckCustomerLoginEligibilityUseCase customerLoginEligibility(
            CustomerDirectory customers, CustomerLoginEligibilityProperties properties) {
        return new CheckCustomerLoginEligibilityService(customers,
                Duration.ofMillis(properties.statusMaxAgeMs()));
    }
}
