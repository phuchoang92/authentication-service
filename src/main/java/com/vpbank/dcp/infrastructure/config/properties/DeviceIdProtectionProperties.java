package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.device-id")
public record DeviceIdProtectionProperties(@NotBlank String lookupKeyId,
                                           @NotBlank String lookupKeyBase64,
                                           @NotBlank String encryptionKeyId,
                                           @NotBlank String encryptionKeyBase64) {
    @Override
    public String toString() {
        return "DeviceIdProtectionProperties[redacted]";
    }
}
