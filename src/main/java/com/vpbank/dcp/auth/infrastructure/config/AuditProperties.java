package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Security activity audit (slice 9). {@code queueCapacity} bounds the memory a burst may take before events
 * are dropped; {@code batchSize} is the most rows one insert transaction carries; {@code shutdownDrain} is how
 * long a clean shutdown waits for the writer before writing the rest itself.
 */
@Validated
@ConfigurationProperties(prefix = "auth.audit")
public record AuditProperties(
        @DefaultValue("false") boolean enabled,
        @Min(100) @Max(1_000_000) @DefaultValue("10000") int queueCapacity,
        @Min(1) @Max(1000) @DefaultValue("100") int batchSize,
        @NotNull @DurationMin(millis = 100) @DefaultValue("PT2S") Duration shutdownDrain) {
}
