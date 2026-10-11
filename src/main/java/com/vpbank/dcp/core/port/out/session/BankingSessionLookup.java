package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import java.util.Objects;
import java.util.UUID;

/** Pre-read only. It does not authorize any banking action. */
public record BankingSessionLookup(LookupKeyVersion lookupVersion, Digest32 lookupDigest,
                                   UUID generation, UUID sessionId, UUID subjectId,
                                   UUID bindingId, String appId, RequestKeyThumbprint requestKey) {
    public BankingSessionLookup {
        Objects.requireNonNull(lookupVersion);
        Objects.requireNonNull(lookupDigest);
        Objects.requireNonNull(generation);
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(subjectId);
        Objects.requireNonNull(bindingId);
        Objects.requireNonNull(appId);
        Objects.requireNonNull(requestKey);
    }
}
