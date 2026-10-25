package com.vpbank.dcp.core.password;

import java.util.Objects;
import java.util.UUID;

/**
 * The non-secret facts the App proofs must bind before credential dispatch.
 */
public record PasswordOperationContext(UUID operationId,
                                       String appId,
                                       String platform,
                                       String deviceId,
                                       String username,
                                       String claimedBindingId) {

    public PasswordOperationContext {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(deviceId, "installationId");
        Objects.requireNonNull(username, "username");
        if (appId.isBlank() || deviceId.isBlank() || username.isBlank()
                || !("ANDROID".equals(platform) || "IOS".equals(platform))) {
            throw new IllegalArgumentException("Password operation is invalid");
        }
        if (claimedBindingId != null
                && (claimedBindingId.length() < 16 || claimedBindingId.length() > 300)) {
            throw new IllegalArgumentException("Password operation is invalid");
        }
    }

    @Override
    public String toString() {
        return "PasswordOperationContext[redacted]";
    }
}
