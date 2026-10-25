package com.vpbank.dcp.core.security;

/** Verifies a compact DPoP proof; shared replay reservation is a separate authority operation. */
public interface DpopProofDecoder {
    VerifiedDpopProof verify(String compact, DpopExpectation expectation);
}
