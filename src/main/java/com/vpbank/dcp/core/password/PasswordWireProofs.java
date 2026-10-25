package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.security.VerifiedDpopProof;
import java.util.Objects;

/** Opaque wire proofs are never included in generated record output. */
public final class PasswordWireProofs {

    private final VerifiedDpopProof dpop;
    private final String requestKeyProof;
    private final String deviceProof;
    private final String responsePublicJwk;

    public PasswordWireProofs(VerifiedDpopProof dpop, String requestKeyProof,
                              String deviceProof, String responsePublicJwk) {
        this.dpop = Objects.requireNonNull(dpop, "dpop");
        this.requestKeyProof = Objects.requireNonNull(requestKeyProof, "requestKeyProof");
        this.deviceProof = deviceProof;
        this.responsePublicJwk = Objects.requireNonNull(responsePublicJwk, "responsePublicJwk");
    }

    public VerifiedDpopProof dpop() { return dpop; }
    public String requestKeyProof() { return requestKeyProof; }
    public String deviceProof() { return deviceProof; }
    public String responsePublicJwk() { return responsePublicJwk; }

    @Override
    public String toString() {
        return "PasswordWireProofs[redacted]";
    }
}
