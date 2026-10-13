package com.vpbank.dcp.infrastructure.persistence.codec;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** A scoped active key and retained verification/decryption keys; never log this value. */
public final class DeviceIdKeyMaterial {
    private final String activeKeyId;
    private final Map<String, byte[]> keys;

    public DeviceIdKeyMaterial(String activeKeyId, Map<String, byte[]> keys) {
        Objects.requireNonNull(activeKeyId);
        Objects.requireNonNull(keys);
        if (!activeKeyId.matches("[A-Za-z0-9._-]{1,64}") || keys.isEmpty()) {
            throw new InvalidDeviceIdProtectionException();
        }
        Map<String, byte[]> copies = new LinkedHashMap<>();
        byte[] activeKey = keys.get(activeKeyId);
        if (activeKey == null || activeKey.length != 32) {
            throw new InvalidDeviceIdProtectionException();
        }
        copies.put(activeKeyId, activeKey.clone());
        keys.forEach((keyId, bytes) -> {
            if (keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,64}")
                    || bytes == null || bytes.length != 32) {
                throw new InvalidDeviceIdProtectionException();
            }
            copies.putIfAbsent(keyId, bytes.clone());
        });
        if (!copies.containsKey(activeKeyId)) {
            throw new InvalidDeviceIdProtectionException();
        }
        this.activeKeyId = activeKeyId;
        this.keys = Collections.unmodifiableMap(copies);
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    public byte[] key(String keyId) {
        byte[] key = keys.get(keyId);
        if (key == null) {
            throw new InvalidDeviceIdProtectionException();
        }
        return key.clone();
    }

    public Set<String> acceptedKeyIds() {
        return keys.keySet();
    }

    @Override
    public String toString() {
        return "DeviceIdKeyMaterial[redacted]";
    }
}
