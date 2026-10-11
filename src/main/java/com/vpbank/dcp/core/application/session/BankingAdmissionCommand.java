package com.vpbank.dcp.core.application.session;

import java.net.URI;
import java.util.Objects;

/** BFF-provided original request and server-mapped action, with token and proof redacted. */
public record BankingAdmissionCommand(String exactToken, String dpopProof, String method,
                                      URI externalUri, String targetAction, String audience) {
    public BankingAdmissionCommand {
        Objects.requireNonNull(exactToken);
        Objects.requireNonNull(dpopProof);
        Objects.requireNonNull(method);
        Objects.requireNonNull(externalUri);
        Objects.requireNonNull(targetAction);
        Objects.requireNonNull(audience);
    }

    @Override public String toString() { return "BankingAdmissionCommand[redacted]"; }
}
