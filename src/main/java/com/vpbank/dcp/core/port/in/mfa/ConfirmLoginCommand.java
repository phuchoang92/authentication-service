package com.vpbank.dcp.core.port.in.mfa;

import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.time.Instant;
import java.util.Objects;

/**
 * Confirms a login whose MFA was elevated at the MFA service. Auth re-checks the transaction
 * itself, so the App sends no factor material here. The HTTP boundary verifies DPoP method,
 * URI, nonce and token hash first.
 */
public record ConfirmLoginCommand(SessionTokenLookup pendingToken, VerifiedDpopProof dpop,
                                  Instant now) {
    public ConfirmLoginCommand {
        Objects.requireNonNull(pendingToken);
        Objects.requireNonNull(dpop);
        Objects.requireNonNull(now);
    }

    @Override
    public String toString() {
        return "ConfirmLoginCommand[redacted]";
    }
}
