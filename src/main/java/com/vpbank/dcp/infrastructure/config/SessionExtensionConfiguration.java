package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.session.ExtendSessionService;
import com.vpbank.dcp.core.session.SessionActivityStore;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisSessionActivityStore;
import com.vpbank.dcp.infrastructure.config.properties.IngressProperties;
import com.vpbank.dcp.infrastructure.config.properties.SessionExtensionProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Clock;
import java.time.Duration;

/**
 * Integration-only BFF → Auth idle sliding (flow 16), gated exactly like the password login
 * slice. Only the session hash is checked; Valkey guards are an open gate.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@EnableConfigurationProperties(SessionExtensionProperties.class)
public class SessionExtensionConfiguration {

    @Bean
    SessionActivityStore sessionActivityStore(StringRedisTemplate redis, RedisServerIdentity identity) {
        return new RedisSessionActivityStore(redis, identity);
    }

    @Bean
    ExtendSessionService extendSessionService(SessionActivityStore store, Clock clock,
                                              SessionExtensionProperties properties,
                                              IngressProperties ingress) {
        if (!ingress.allowedWorkloadUris().contains(properties.bffWorkloadUri())) {
            // Otherwise the BFF could never pass mTLS and every call would fail.
            throw new IllegalStateException(
                    "auth.session-extension.bff-workload-uri must be one of auth.ingress.allowed-workload-uris");
        }
        return new ExtendSessionService(store, clock, properties.activityRoutes(),
                Duration.ofMillis(properties.maxAdmissionAgeMs()),
                Duration.ofMillis(properties.maxClockSkewMs()));
    }
}
