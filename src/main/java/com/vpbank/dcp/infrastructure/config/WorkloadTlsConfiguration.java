package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.infrastructure.config.properties.WorkloadTlsProperties;
import java.net.http.HttpClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(WorkloadTlsProperties.class)
public class WorkloadTlsConfiguration {

    @Bean
    HttpClient workloadHttpClient(WorkloadTlsProperties properties) {
        return new WorkloadHttpClientFactory().create(properties);
    }
}
