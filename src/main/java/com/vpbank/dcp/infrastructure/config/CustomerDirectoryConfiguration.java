package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.infrastructure.adapter.out.customer.HttpCustomerDirectory;
import com.vpbank.dcp.infrastructure.config.properties.CustomerDirectoryProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(CustomerDirectoryProperties.class)
public class CustomerDirectoryConfiguration {

    @Bean
    CustomerDirectory customerDirectory(HttpClient workloadHttpClient,
                                        CustomerDirectoryProperties properties,
                                        JsonMapper json) {
        return new HttpCustomerDirectory(
                workloadHttpClient,
                URI.create(properties.origin()),
                Duration.ofMillis(properties.requestTimeoutMs()),
                json);
    }
}
