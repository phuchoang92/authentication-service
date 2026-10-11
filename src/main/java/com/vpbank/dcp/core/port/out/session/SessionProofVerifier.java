package com.vpbank.dcp.core.port.out.session;

import java.net.URI;
import java.time.Instant;

public interface SessionProofVerifier {
    VerifiedSessionProof verify(String exactToken, String compactProof, String method,
                                URI externalUri, BankingSessionLookup lookup, Instant now);
}
