package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Secret-bearing deployment input; intentionally redacted when rendered.
 */
@Validated
@ConfigurationProperties(prefix = "auth.workload.tls")
public record WorkloadTlsProperties(
        @NotBlank String keyStore,
        @NotBlank String keyStorePassword,
        @NotBlank String trustStore,
        @NotBlank String trustStorePassword,
        @Min(1) @Max(2000) long connectTimeoutMs) {

    @Override
    public String toString() {
        return "WorkloadTlsProperties[redacted]";
    }
}
