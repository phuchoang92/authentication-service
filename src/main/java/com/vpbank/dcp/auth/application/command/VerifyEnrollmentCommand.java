package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import java.util.Objects;

/** Step 2: the challenge, decrypted by the device and re-encrypted to Ksrv (compact JWE text). */
public record VerifyEnrollmentCommand(OpaqueToken token, String challengeResponse) {
    public VerifyEnrollmentCommand {
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(challengeResponse, "challengeResponse");
    }

    @Override
    public String toString() {
        return "VerifyEnrollmentCommand[redacted]";
    }
}
