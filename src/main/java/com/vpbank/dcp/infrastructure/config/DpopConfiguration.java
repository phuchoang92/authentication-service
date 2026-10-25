package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.security.DpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.DpopAlgorithmPolicy;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidDpopConfigurationException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.NonProductionDpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.SpringDpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.config.properties.DpopProperties;
import java.util.Arrays;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties(DpopProperties.class)
public class DpopConfiguration {
    private static final Logger LOGGER = LoggerFactory.getLogger(DpopConfiguration.class);
    private static final Set<String> NON_PRODUCTION_PROFILES = Set.of(
            "local", "dev", "test", "qa", "uat", "staging", "integration", "non-prod");

    @Bean
    DpopAlgorithmPolicy dpopAlgorithmPolicy(DpopProperties properties) {
        return new DpopAlgorithmPolicy(properties.allowedAlgorithms());
    }

    @Bean
    DpopProofDecoder dpopProofDecoder(DpopProperties properties, DpopAlgorithmPolicy algorithms,
                                      Sha256Digests digests, StrictJoseJson json, Environment environment) {
        if (properties.enabled()) {
            return new SpringDpopProofDecoder(digests, json, algorithms);
        }
        String[] profiles = environment.getActiveProfiles();
        if (profiles.length == 0 || !Arrays.stream(profiles).allMatch(NON_PRODUCTION_PROFILES::contains)) {
            throw new InvalidDpopConfigurationException();
        }
        LOGGER.warn("DPoP verification is disabled for explicitly configured non-production profiles");
        return new NonProductionDpopProofDecoder(digests, json, algorithms);
    }
}
