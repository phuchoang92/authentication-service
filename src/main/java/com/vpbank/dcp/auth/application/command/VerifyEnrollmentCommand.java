package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import lombok.NonNull;

/** Step 2: the challenge, decrypted by the device and re-encrypted to Ksrv (compact JWE text). */
public record VerifyEnrollmentCommand(@NonNull AdmittedSession admitted, @NonNull String challengeResponse) {
    @Override
    public String toString() {
        return "VerifyEnrollmentCommand[redacted]";
    }
}
