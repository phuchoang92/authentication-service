package com.vpbank.dcp.infrastructure.adapter.out.totp;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Key material is supplied by configuration/secret management, never by a request. */
public final class TotpSecretKeys {
    private final String activeKeyId;
    private final Map<String, byte[]> keys;

    public TotpSecretKeys(String activeKeyId, Map<String, byte[]> keys) {
        if (!validKeyId(activeKeyId) || keys == null || !keys.containsKey(activeKeyId)) {
            throw new InvalidTotpSecretException();
        }
        Map<String, byte[]> copy = new HashMap<>();
        keys.forEach((keyId, key) -> {
            if (!validKeyId(keyId) || key == null || key.length != 32) {
                throw new InvalidTotpSecretException();
            }
            copy.put(keyId, key.clone());
        });
        this.activeKeyId = activeKeyId;
        this.keys = Map.copyOf(copy);
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    byte[] key(String keyId) {
        byte[] key = keys.get(Objects.requireNonNull(keyId, "keyId"));
        if (key == null) {
            throw new InvalidTotpSecretException();
        }
        return key.clone();
    }

    private static boolean validKeyId(String keyId) {
        return keyId != null && keyId.matches("[A-Za-z0-9._-]{1,64}");
    }

    @Override
    public String toString() {
        return "TotpSecretKeys[redacted]";
    }
}
