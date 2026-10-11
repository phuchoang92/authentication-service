package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import java.util.Map;

/** BFF workload payload. Password and proofs are deliberately excluded from toString. */
public record ForwardPasswordRequest(Original original, Command command) {
    @Override public String toString() { return "ForwardPasswordRequest[redacted]"; }

    public record Original(String method, String publicUri, String dpopProof,
                           String opaqueToken, String bodyBase64, String idempotencyKey) {
        @Override public String toString() { return "Original[redacted]"; }
    }

    public record Command(String appId, String platform, String installationId,
                          String username, String password, String deviceBindingId,
                          ResponseKey responseKey, String requestKeyProof, String deviceProof) {
        @Override public String toString() { return "Command[redacted]"; }
    }

    public record ResponseKey(Integer version, String algorithm, String format,
                              Map<String, String> publicJwk) {
        @Override public String toString() { return "ResponseKey[redacted]"; }
    }
}
