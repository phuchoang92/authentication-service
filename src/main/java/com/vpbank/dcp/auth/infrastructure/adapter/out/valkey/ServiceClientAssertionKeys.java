package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

/**
 * Key factory for used service client assertion IDs (slice 12):
 * {@code service-client-assertion:used:v1:<SHA-256 of the ID, base64url>}.
 */
public final class ServiceClientAssertionKeys implements UsedAssertionKeys {
    static final String PREFIX = "service-client-assertion:used:v1:";

    @Override
    public String forAssertionId(String assertionId) {
        return PREFIX + AssertionIdDigest.of(assertionId);
    }
}
