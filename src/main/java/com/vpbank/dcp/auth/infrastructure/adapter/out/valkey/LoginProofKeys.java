package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

/**
 * Key factory for used login device-proof IDs (slice 13): {@code login-proof:used:v1:<SHA-256 of the ID, base64url>}.
 */
public final class LoginProofKeys implements UsedAssertionKeys {
    static final String PREFIX = "login-proof:used:v1:";

    @Override
    public String forAssertionId(String assertionId) {
        return PREFIX + AssertionIdDigest.of(assertionId);
    }
}
