package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import java.util.Objects;
import java.util.UUID;

public record PasswordReplayAttempt(UUID operationId, RequestKeyThumbprint requestKey,
                                    Digest32 deviceKeyThumbprint,
                                    PasswordProofIds proofIds) {

    public PasswordReplayAttempt {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(proofIds, "proofIds");
        if ((deviceKeyThumbprint == null) != (proofIds.deviceKey() == null)) {
            throw new IllegalArgumentException("Password operation is invalid");
        }
    }
}
