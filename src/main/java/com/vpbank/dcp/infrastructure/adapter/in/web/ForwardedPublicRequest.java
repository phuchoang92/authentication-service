package com.vpbank.dcp.infrastructure.adapter.in.web;

/** Exact public request details forwarded by the authenticated BFF. */
public record ForwardedPublicRequest(String method, String publicUri, String dpopProof,
                                     String opaqueToken, String bodyBase64, String idempotencyKey) {

    @Override
    public String toString() {
        return "ForwardedPublicRequest[redacted]";
    }
}
