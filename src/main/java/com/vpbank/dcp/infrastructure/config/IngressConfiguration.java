package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.config.properties.IngressProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(IngressProperties.class)
public class IngressConfiguration {

    @Bean
    ExternalUriPolicy externalUriPolicy(IngressProperties properties) {
        return new ExternalUriPolicy(properties.externalOrigin());
    }

}
