package com.vpbank.dcp.core.port.in.mfa;

import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.time.Instant;
import java.util.Objects;

/** The HTTP boundary verifies DPoP method, URI, nonce and token hash first. */
public record TotpLoginCommand(String challengeId, SessionTokenLookup pendingToken,
                               VerifiedDpopProof dpop, String encryptedCode, Instant now) {
    public TotpLoginCommand {
        Objects.requireNonNull(challengeId);
        Objects.requireNonNull(pendingToken);
        Objects.requireNonNull(dpop);
        Objects.requireNonNull(encryptedCode);
        Objects.requireNonNull(now);
    }

    @Override
    public String toString() {
        return "TotpLoginCommand[redacted]";
    }
}
