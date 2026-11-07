package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import lombok.NonNull;

/** Step 3: ask Auth to check the MFA outcome; {@code tokenEncryptionKey} seals the new ACTIVE session's token. */
public record ConfirmEnrollmentCommand(@NonNull AdmittedSession admitted, @NonNull String tokenEncryptionKey) {
    @Override
    public String toString() {
        return "ConfirmEnrollmentCommand[redacted]";
    }
}
