package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Server-owned values for one typed enrollment transaction. */
public record ExpectedEnrollmentProof(
        UUID enrollmentId, String purpose, String appId,
        RequestKeyThumbprint requestKey, Digest32 tokenHash,
        Digest32 signingInputHash, Digest32 newKeyThumbprint,
        Digest32 commandHash, Instant now) {

    public ExpectedEnrollmentProof {
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(appId, "appId");
        Objects.requireNonNull(requestKey, "requestKey");
        Objects.requireNonNull(tokenHash, "tokenHash");
        Objects.requireNonNull(signingInputHash, "signingInputHash");
        Objects.requireNonNull(newKeyThumbprint, "newKeyThumbprint");
        Objects.requireNonNull(commandHash, "commandHash");
        Objects.requireNonNull(now, "now");
        if (purpose.isBlank() || appId.isBlank()) {
            throw new InvalidCryptographicInputException();
        }
    }
}
