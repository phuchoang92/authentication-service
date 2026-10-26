package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Session deadlines. The token carries channel and session ID in clear (slice 7), so no lookup key material is needed. */
@Validated
@ConfigurationProperties(prefix = "auth.session")
public record SessionProperties(
        @NotNull @DurationMin(seconds = 1) @DefaultValue("PT15M") Duration idle,
        @NotNull @DurationMin(seconds = 1) @DefaultValue("PT20M") Duration absolute,
        @NotNull @DefaultValue("PT30S") Duration maxAdmittedAtSkew) {

    @Override
    public String toString() {
        return "SessionProperties[idle=" + idle + ", absolute=" + absolute + ", maxAdmittedAtSkew=" + maxAdmittedAtSkew + "]";
    }
}
