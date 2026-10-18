package com.vpbank.dcp.infrastructure.adapter.out.mfa;

import java.util.List;

/** Idempotent on {@code authOperationId}: the same ID with the same body is the same transaction. */
record MfaCreateRequest(String purpose, String customerNumber, String channel,
                        String authOperationId, List<String> factors, String notAfter,
                        String contextDigest) {
    @Override
    public String toString() {
        return "MfaCreateRequest[redacted]";
    }
}
