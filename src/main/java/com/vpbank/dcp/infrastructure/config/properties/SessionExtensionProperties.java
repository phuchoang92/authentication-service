package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Set;

/**
 * {@code bffWorkloadUri} is the only mTLS URI SAN allowed to extend sessions.
 * {@code activityRoutes} are the BFF route IDs that count as user activity.
 */
@Validated
@ConfigurationProperties(prefix = "auth.session-extension")
public record SessionExtensionProperties(@NotBlank String bffWorkloadUri,
                                         @NotEmpty Set<String> activityRoutes,
                                         @Positive long maxAdmissionAgeMs,
                                         @PositiveOrZero long maxClockSkewMs) {

    public SessionExtensionProperties {
        activityRoutes = activityRoutes == null ? null : Set.copyOf(activityRoutes);
    }
}
