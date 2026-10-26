package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/**
 * Slice 6: the new device presents the scanned authorization token from the same restricted session that
 * made the request, with the public JWK its new ACTIVE session token must be sealed to.
 */
public record ClaimEnrollmentCommand(OpaqueToken token, String authorizationToken, String tokenEncryptionKey) {
    public ClaimEnrollmentCommand {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(authorizationToken, "authorizationToken");
        Objects.requireNonNull(tokenEncryptionKey, "tokenEncryptionKey");
    }

    @Override
    public String toString() {
        return "ClaimEnrollmentCommand[redacted]";
    }
}
