package com.vpbank.dcp.core.port.out.password;

import java.net.URI;
import java.util.Objects;

/** Opaque wire proofs are never included in generated record output. */
public final class PasswordWireProofs {

    private final URI externalUri;
    private final String dpop;
    private final String requestKeyProof;
    private final String deviceProof;
    private final String responsePublicJwk;

    public PasswordWireProofs(URI externalUri, String dpop, String requestKeyProof,
                              String deviceProof, String responsePublicJwk) {
        this.externalUri = Objects.requireNonNull(externalUri, "externalUri");
        this.dpop = Objects.requireNonNull(dpop, "dpop");
        this.requestKeyProof = Objects.requireNonNull(requestKeyProof, "requestKeyProof");
        this.deviceProof = deviceProof;
        this.responsePublicJwk = Objects.requireNonNull(responsePublicJwk, "responsePublicJwk");
    }

    public URI externalUri() { return externalUri; }
    public String dpop() { return dpop; }
    public String requestKeyProof() { return requestKeyProof; }
    public String deviceProof() { return deviceProof; }
    public String responsePublicJwk() { return responsePublicJwk; }

    @Override
    public String toString() {
        return "PasswordWireProofs[redacted]";
    }
}
