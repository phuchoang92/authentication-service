package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common;

import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * How the app's device ID is stored (phase 3): a keyed lookup digest for queries and an AEAD
 * ciphertext for display, each tagged with its key ID so keys can rotate. The HMAC and AES keys
 * are distinct. AAD binds the ciphertext to its owner, so a row copied between customers does
 * not decrypt. No I/O, no clock; keys arrive validated from configuration.
 */
public final class DeviceIdProtection {
    static final byte CIPHERTEXT_VERSION = 1;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final String HMAC = "HmacSHA256";
    private static final String AEAD = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final Map<String, byte[]> lookupKeys;
    private final String lookupKeyId;
    private final Map<String, byte[]> encryptionKeys;
    private final String encryptionKeyId;
    private final SecureRandom random;

    public DeviceIdProtection(Map<String, byte[]> lookupKeys, String lookupKeyId,
                              Map<String, byte[]> encryptionKeys, String encryptionKeyId, SecureRandom random) {
        this.lookupKeys = checked(lookupKeys, lookupKeyId, 32, "lookup");
        this.lookupKeyId = lookupKeyId;
        this.encryptionKeys = checked(encryptionKeys, encryptionKeyId, 32, "encryption");
        this.encryptionKeyId = encryptionKeyId;
        this.random = Objects.requireNonNull(random, "random");
    }

    public String lookupKeyId() {
        return lookupKeyId;
    }

    public String encryptionKeyId() {
        return encryptionKeyId;
    }

    /** HMAC-SHA256(key, customerId ‖ channel ‖ deviceId) with the current lookup key: 32 bytes. */
    public byte[] lookup(CustomerId customerId, Channel channel, DeviceId deviceId) {
        return lookup(lookupKeyId, customerId, channel, deviceId);
    }

    public byte[] lookup(String keyId, CustomerId customerId, Channel channel, DeviceId deviceId) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key(lookupKeys, keyId, "lookup"), HMAC));
            return mac.doFinal(canonical(customerId, channel, deviceId.value()));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("HmacSHA256 is not available", failure);
        }
    }

    /** {@code version ‖ nonce ‖ ciphertext ‖ tag} under the current encryption key, AAD = customerId ‖ channel. */
    public byte[] encrypt(CustomerId customerId, Channel channel, DeviceId deviceId) {
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(AEAD);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key(encryptionKeys, encryptionKeyId, "encryption"), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(customerId, channel));
            byte[] sealed = cipher.doFinal(deviceId.value().getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.allocate(1 + NONCE_BYTES + sealed.length).put(CIPHERTEXT_VERSION).put(nonce).put(sealed).array();
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("AES-GCM is not available", failure);
        }
    }

    /** Empty when the key ID is unknown, the owner differs, or the bytes were tampered with. */
    public Optional<DeviceId> decrypt(String keyId, byte[] ciphertext, CustomerId customerId, Channel channel) {
        if (ciphertext == null || ciphertext.length < 1 + NONCE_BYTES + TAG_BITS / 8
                || ciphertext[0] != CIPHERTEXT_VERSION || !encryptionKeys.containsKey(keyId)) {
            return Optional.empty();
        }
        try {
            Cipher cipher = Cipher.getInstance(AEAD);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKeys.get(keyId), "AES"),
                    new GCMParameterSpec(TAG_BITS, ciphertext, 1, NONCE_BYTES));
            cipher.updateAAD(aad(customerId, channel));
            byte[] plain = cipher.doFinal(ciphertext, 1 + NONCE_BYTES, ciphertext.length - 1 - NONCE_BYTES);
            return Optional.of(new DeviceId(new String(plain, StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException | IllegalArgumentException invalid) {
            return Optional.empty();
        }
    }

    /** Length-prefixed fields: "ab"+"c" and "a"+"bc" give different input. */
    private static byte[] canonical(CustomerId customerId, Channel channel, String deviceId) {
        StringBuilder canonical = new StringBuilder();
        for (String field : new String[]{customerId.value(), channel.name(), deviceId}) {
            canonical.append(field.length()).append(':').append(field).append(';');
        }
        return canonical.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] aad(CustomerId customerId, Channel channel) {
        return canonical(customerId, channel, "");
    }

    private static byte[] key(Map<String, byte[]> keys, String keyId, String purpose) {
        byte[] key = keys.get(keyId);
        if (key == null) {
            throw new IllegalArgumentException("No device " + purpose + " key for ID " + keyId);
        }
        return key;
    }

    private static Map<String, byte[]> checked(Map<String, byte[]> keys, String currentId, int minBytes, String purpose) {
        Objects.requireNonNull(keys, purpose + " keys");
        Objects.requireNonNull(currentId, purpose + " key ID");
        if (!keys.containsKey(currentId)) {
            throw new IllegalArgumentException("Device " + purpose + " key ID " + currentId + " has no key");
        }
        keys.forEach((id, key) -> {
            if (!KEY_ID.matcher(id).matches() || key == null || key.length < minBytes) {
                throw new IllegalArgumentException("Device " + purpose + " key " + id + " must have a valid ID and at least "
                        + minBytes + " bytes");
            }
        });
        return Map.copyOf(keys);
    }
}
