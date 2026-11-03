package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import java.util.Objects;

/**
 * Step 1 of device trust from a restricted session. A device Auth does not know yet must send its
 * public P-256 JWK (text) and platform; a known device may send nothing and its stored key is used.
 */
public record InitEnrollmentCommand(AdmittedSession admitted, String devicePublicJwk, DevicePlatform platform) {
    public InitEnrollmentCommand {
        Objects.requireNonNull(admitted, "admitted");
    }

    @Override
    public String toString() {
        return "InitEnrollmentCommand[redacted]";
    }
}
