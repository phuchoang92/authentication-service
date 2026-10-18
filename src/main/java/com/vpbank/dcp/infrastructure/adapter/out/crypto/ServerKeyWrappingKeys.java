package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * AES-256 keys that wrap Ksrv private keys, by key ID. Each wrapped key records the ID it used,
 * so a new active key can be added without re-wrapping everything at once.
 */
public final class ServerKeyWrappingKeys {
    private final String activeKeyId;
    private final Map<String, byte[]> keys;

    public ServerKeyWrappingKeys(String activeKeyId, Map<String, byte[]> keys) {
        Objects.requireNonNull(activeKeyId, "activeKeyId");
        Objects.requireNonNull(keys, "keys");
        this.keys = keys.entrySet().stream().collect(Collectors.toUnmodifiableMap(
                Map.Entry::getKey, entry -> entry.getValue().clone()));
        this.activeKeyId = activeKeyId;
        if (!activeKeyId.matches("[A-Za-z0-9_-]{1,16}") || !this.keys.containsKey(activeKeyId)
                || this.keys.keySet().stream().anyMatch(id -> !id.matches("[A-Za-z0-9_-]{1,16}"))
                || this.keys.values().stream().anyMatch(key -> key.length != 32)) {
            throw new InvalidCryptographicInputException();
        }
    }

    String activeKeyId() {
        return activeKeyId;
    }

    /** A wrapped key whose ID is no longer configured cannot be unwrapped: that is a denial. */
    byte[] key(String keyId) {
        byte[] key = keys.get(keyId);
        if (key == null) {
            throw new InvalidCryptographicInputException();
        }
        return key.clone();
    }

    @Override
    public String toString() {
        return "ServerKeyWrappingKeys[redacted, ids=" + keys.keySet().stream().sorted()
                .collect(Collectors.joining(",")) + "]";
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ServerKeyWrappingKeys that && activeKeyId.equals(that.activeKeyId)
                && keys.keySet().equals(that.keys.keySet())
                && keys.keySet().stream().allMatch(id -> Arrays.equals(keys.get(id), that.keys.get(id)));
    }

    @Override
    public int hashCode() {
        return activeKeyId.hashCode();
    }
}
