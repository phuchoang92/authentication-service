package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import java.util.Objects;

/** Step 3: ask Auth to check the MFA outcome; {@code tokenEncryptionKey} seals the new ACTIVE session's token. */
public record ConfirmEnrollmentCommand(AdmittedSession admitted, String tokenEncryptionKey) {
    public ConfirmEnrollmentCommand {
        Objects.requireNonNull(admitted, "admitted");
        Objects.requireNonNull(tokenEncryptionKey, "tokenEncryptionKey");
    }

    @Override
    public String toString() {
        return "ConfirmEnrollmentCommand[redacted]";
    }
}
