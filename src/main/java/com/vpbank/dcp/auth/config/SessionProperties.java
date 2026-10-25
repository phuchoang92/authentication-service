package com.vpbank.dcp.auth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.Map;

/**
 * Session store settings. {@code lookupHmacKeysBase64} maps token key versions ({@code k1}, …)
 * to ≥32-byte HMAC keys; {@code lookupKeyVersion} is the version new tokens are issued under.
 */
@Validated
@ConfigurationProperties(prefix = "auth.session")
public record SessionProperties(
        @NotBlank @DefaultValue("k1") String lookupKeyVersion,
        @NotEmpty Map<String, String> lookupHmacKeysBase64,
        @NotNull @DurationMin(seconds = 1) @DefaultValue("PT15M") Duration idle,
        @NotNull @DurationMin(seconds = 1) @DefaultValue("PT20M") Duration absolute,
        @NotNull @DefaultValue("PT30S") Duration maxAdmittedAtSkew) {

    @Override
    public String toString() {
        return "SessionProperties[lookupKeyVersion=" + lookupKeyVersion + ", keyVersions="
                + lookupHmacKeysBase64.keySet() + ", idle=" + idle + ", absolute=" + absolute + "]";
    }
}
