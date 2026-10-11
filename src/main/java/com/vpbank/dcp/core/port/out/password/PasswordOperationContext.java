package com.vpbank.dcp.core.port.out.password;

import java.util.Objects;
import java.util.UUID;

/** The non-secret facts the App proofs must bind before credential dispatch. */
public record PasswordOperationContext(UUID operationId, String appId, String platform,
                                       String installationId, String username,
                                       UUID claimedBindingId) {

    public PasswordOperationContext {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(installationId, "installationId");
        Objects.requireNonNull(username, "username");
        if (appId.isBlank() || installationId.isBlank() || username.isBlank()
                || !("ANDROID".equals(platform) || "IOS".equals(platform))) {
            throw new InvalidPasswordOperationException();
        }
    }

    @Override
    public String toString() {
        return "PasswordOperationContext[redacted]";
    }
}
