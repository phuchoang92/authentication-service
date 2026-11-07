package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import java.time.Instant;
import lombok.NonNull;

/**
 * One record as Valkey keeps it: a STRING key, its text, and when the server forgets it.
 */
public record ValkeyRecord(@NonNull String key, @NonNull String text, @NonNull Instant expiresAt) {
    /** The text may hold a flow's secrets; only the key is printed. */
    @Override
    public String toString() {
        return "ValkeyRecord[key=" + key + ", redacted]";
    }
}
