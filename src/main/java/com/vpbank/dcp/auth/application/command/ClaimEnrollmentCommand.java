package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import lombok.NonNull;

/**
 * Slice 6: the new device presents the scanned authorization token from the same restricted session that
 * made the request, with the public JWK its new ACTIVE session token must be sealed to.
 */
public record ClaimEnrollmentCommand(@NonNull AdmittedSession admitted,
                                     @NonNull String authorizationToken,
                                     @NonNull String tokenEncryptionKey) {
    @Override
    public String toString() {
        return "ClaimEnrollmentCommand[redacted]";
    }
}
