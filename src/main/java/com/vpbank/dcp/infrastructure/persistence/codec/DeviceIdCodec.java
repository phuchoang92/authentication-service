package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Protects the App device ID for Auth storage; neither output proves device possession. */
public final class DeviceIdCodec {
    private static final byte FORMAT_VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final DeviceIdKeyMaterial lookupKeys;
    private final DeviceIdKeyMaterial encryptionKeys;
    private final SecureRandom random;

    public DeviceIdCodec(DeviceIdKeyMaterial lookupKeys,
                         DeviceIdKeyMaterial encryptionKeys, SecureRandom random) {
        this.lookupKeys = Objects.requireNonNull(lookupKeys);
        this.encryptionKeys = Objects.requireNonNull(encryptionKeys);
        this.random = Objects.requireNonNull(random);
    }

    public ProtectedDeviceId protect(UUID customerId, String channel,
                                     UUID bindingId, String deviceId) {
        requireIdentity(customerId, channel, deviceId);
        Objects.requireNonNull(bindingId);
        String lookupKeyId = lookupKeys.activeKeyId();
        String encryptionKeyId = encryptionKeys.activeKeyId();
        Digest32 lookup = lookup(customerId, channel, deviceId, lookupKeyId);
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(encryptionKeys.key(encryptionKeyId), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(customerId, channel, bindingId));
            byte[] encrypted = cipher.doFinal(utf8(deviceId));
            byte[] envelope = ByteBuffer.allocate(1 + NONCE_BYTES + encrypted.length)
                    .put(FORMAT_VERSION).put(nonce).put(encrypted).array();
            return new ProtectedDeviceId(lookup, lookupKeyId, envelope, encryptionKeyId);
        } catch (GeneralSecurityException failure) {
            throw new InvalidDeviceIdProtectionException(failure);
        }
    }

    public String reveal(UUID customerId, String channel, UUID bindingId,
                         String encryptionKeyId, byte[] ciphertext) {
        Objects.requireNonNull(customerId);
        Objects.requireNonNull(bindingId);
        Objects.requireNonNull(ciphertext);
        if (channel == null || channel.isBlank() || ciphertext.length < 1 + NONCE_BYTES + 16
                || ciphertext[0] != FORMAT_VERSION) {
            throw new InvalidDeviceIdProtectionException();
        }
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(ciphertext, 1, nonce, 0, NONCE_BYTES);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(encryptionKeys.key(encryptionKeyId), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(customerId, channel, bindingId));
            byte[] plain = cipher.doFinal(ciphertext, 1 + NONCE_BYTES,
                    ciphertext.length - 1 - NONCE_BYTES);
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plain)).toString();
        } catch (GeneralSecurityException | CharacterCodingException failure) {
            throw new InvalidDeviceIdProtectionException(failure);
        }
    }

    public List<DeviceIdLookup> lookupCandidates(UUID customerId, String channel,
                                                  String deviceId) {
        requireIdentity(customerId, channel, deviceId);
        List<DeviceIdLookup> candidates = new ArrayList<>();
        for (String keyId : lookupKeys.acceptedKeyIds()) {
            candidates.add(new DeviceIdLookup(keyId,
                    lookup(customerId, channel, deviceId, keyId)));
        }
        return List.copyOf(candidates);
    }

    private Digest32 lookup(UUID customerId, String channel, String deviceId,
                            String keyId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(lookupKeys.key(keyId), "HmacSHA256"));
            return Digest32.fromBytes(mac.doFinal(encode(
                    "BANK_DEVICE_ID_LOOKUP_V1", customerId.toString(), channel, deviceId)));
        } catch (GeneralSecurityException failure) {
            throw new InvalidDeviceIdProtectionException(failure);
        }
    }

    private static byte[] aad(UUID customerId, String channel, UUID bindingId) {
        return encode("BANK_DEVICE_ID_CIPHERTEXT_V1", customerId.toString(),
                channel, bindingId.toString());
    }

    private static byte[] encode(String... fields) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (String field : fields) {
            byte[] bytes = utf8(field);
            output.writeBytes(ByteBuffer.allocate(4).putInt(bytes.length).array());
            output.writeBytes(bytes);
        }
        return output.toByteArray();
    }

    private static byte[] utf8(String value) {
        Objects.requireNonNull(value);
        if (!StandardCharsets.UTF_8.newEncoder().canEncode(value)) {
            throw new InvalidDeviceIdProtectionException();
        }
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void requireIdentity(UUID customerId, String channel, String deviceId) {
        Objects.requireNonNull(customerId);
        if (channel == null || channel.isBlank() || channel.length() > 64
                || deviceId == null || deviceId.length() < 16
                || deviceId.length() > 300) {
            throw new InvalidDeviceIdProtectionException();
        }
        utf8(channel);
        utf8(deviceId);
    }
}
