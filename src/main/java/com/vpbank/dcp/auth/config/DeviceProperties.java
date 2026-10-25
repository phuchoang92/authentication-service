package com.vpbank.dcp.auth.config;

import jakarta.validation.constraints.Min;
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
 * Trusted-device settings (slice 4). Two key rings, each ≥ 32 bytes per entry: the HMAC lookup
 * keys and the AES-256-GCM keys that protect the app's device ID, with the ID new rows use.
 */
@Validated
@ConfigurationProperties(prefix = "auth.device")
public record DeviceProperties(
        @NotBlank @DefaultValue("d1") String lookupKeyId,
        @NotEmpty Map<String, String> lookupHmacKeysBase64,
        @NotBlank @DefaultValue("e1") String encryptionKeyId,
        @NotEmpty Map<String, String> encryptionKeysBase64,
        @NotNull @DurationMin(days = 1) @DefaultValue("P180D") Duration trustDuration,
        @Min(1) @DefaultValue("5") int maxLiveDevices,
        @NotNull @DurationMin(seconds = 60) @DefaultValue("PT10M") Duration restrictedSessionTtl) {

    @Override
    public String toString() {
        return "DeviceProperties[lookupKeyId=" + lookupKeyId + ", lookupKeys=" + lookupHmacKeysBase64.keySet()
                + ", encryptionKeyId=" + encryptionKeyId + ", encryptionKeys=" + encryptionKeysBase64.keySet()
                + ", trustDuration=" + trustDuration + ", maxLiveDevices=" + maxLiveDevices + "]";
    }
}
