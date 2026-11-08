package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

/**
 * The Valkey image the integration tests run against: {@code valkey/valkey:9.1} unless {@code -Dvalkey.image=…}
 * says otherwise. The stores need Valkey 8.1 ({@code SET … IFEQ}); run once with {@code valkey/valkey:8.1-alpine}
 * to prove it.
 */
public final class ValkeyImage {
    private ValkeyImage() {
    }

    public static String underTest() {
        return System.getProperty("valkey.image", "valkey/valkey:9.1");
    }
}
