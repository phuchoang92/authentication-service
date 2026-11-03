package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

/**
 * Key factory for used BFF assertion IDs (DD 20 §6a): {@code bff-assertion:used:v1:<SHA-256 of the ID, base64url>}.
 */
public final class BffAssertionKeys implements UsedAssertionKeys {
    static final String PREFIX = "bff-assertion:used:v1:";

    @Override
    public String forAssertionId(String assertionId) {
        return PREFIX + AssertionIdDigest.of(assertionId);
    }
}
