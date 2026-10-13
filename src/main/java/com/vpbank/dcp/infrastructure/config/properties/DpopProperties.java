package com.vpbank.dcp.infrastructure.config.properties;

import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "auth.dpop")
public record DpopProperties(@DefaultValue("true") boolean enabled,
                             @DefaultValue("ES256") Set<String> allowedAlgorithms) {
    public DpopProperties {
        allowedAlgorithms = Set.copyOf(allowedAlgorithms);
    }
}
