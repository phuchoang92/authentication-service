package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.infrastructure.adapter.out.customer.HttpCustomerDirectory;
import com.vpbank.dcp.infrastructure.adapter.out.customer.CustomerHttpEndpoints;
import com.vpbank.dcp.infrastructure.adapter.out.customer.InvalidCustomerDirectoryConfigurationException;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import com.vpbank.dcp.infrastructure.adapter.out.http.InvalidExternalHttpSettingsException;
import com.vpbank.dcp.infrastructure.config.properties.CustomerDirectoryProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(CustomerDirectoryProperties.class)
public class CustomerDirectoryConfiguration {

    private static final int MAX_CUSTOMER_RESPONSE_BYTES = 4096;

    @Bean
    CustomerDirectory customerDirectory(HttpClient workloadHttpClient,
                                        CustomerDirectoryProperties properties) {
        ExternalHttpSettings settings = new ExternalHttpSettings(
                URI.create(properties.origin()), Duration.ofMillis(properties.requestTimeoutMs()),
                MAX_CUSTOMER_RESPONSE_BYTES, CustomerHttpEndpoints.allowedRoutes());
        try {
            ExternalHttpClient customerHttp = new ExternalHttpClient(workloadHttpClient, settings);
            return new HttpCustomerDirectory(customerHttp);
        } catch (InvalidExternalHttpSettingsException failure) {
            throw new InvalidCustomerDirectoryConfigurationException(failure);
        }
    }
}
