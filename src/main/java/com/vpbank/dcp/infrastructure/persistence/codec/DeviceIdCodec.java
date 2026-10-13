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

/** Protects an App installation ID for Auth storage; neither output proves device possession. */
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

    public ProtectedDeviceId protect(UUID customerId, String appId,
                                     UUID bindingId, String installationId) {
        requireIdentity(customerId, appId, installationId);
        Objects.requireNonNull(bindingId);
        String lookupKeyId = lookupKeys.activeKeyId();
        String encryptionKeyId = encryptionKeys.activeKeyId();
        Digest32 lookup = lookup(customerId, appId, installationId, lookupKeyId);
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(encryptionKeys.key(encryptionKeyId), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(customerId, appId, bindingId));
            byte[] encrypted = cipher.doFinal(utf8(installationId));
            byte[] envelope = ByteBuffer.allocate(1 + NONCE_BYTES + encrypted.length)
                    .put(FORMAT_VERSION).put(nonce).put(encrypted).array();
            return new ProtectedDeviceId(lookup, lookupKeyId, envelope, encryptionKeyId);
        } catch (GeneralSecurityException failure) {
            throw new InvalidDeviceIdProtectionException(failure);
        }
    }

    public String reveal(UUID customerId, String appId, UUID bindingId,
                         String encryptionKeyId, byte[] ciphertext) {
        Objects.requireNonNull(customerId);
        Objects.requireNonNull(bindingId);
        Objects.requireNonNull(ciphertext);
        if (appId == null || appId.isBlank() || ciphertext.length < 1 + NONCE_BYTES + 16
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
            cipher.updateAAD(aad(customerId, appId, bindingId));
            byte[] plain = cipher.doFinal(ciphertext, 1 + NONCE_BYTES,
                    ciphertext.length - 1 - NONCE_BYTES);
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plain)).toString();
        } catch (GeneralSecurityException | CharacterCodingException failure) {
            throw new InvalidDeviceIdProtectionException(failure);
        }
    }

    public List<DeviceIdLookup> lookupCandidates(UUID customerId, String appId,
                                                  String installationId) {
        requireIdentity(customerId, appId, installationId);
        List<DeviceIdLookup> candidates = new ArrayList<>();
        for (String keyId : lookupKeys.acceptedKeyIds()) {
            candidates.add(new DeviceIdLookup(keyId,
                    lookup(customerId, appId, installationId, keyId)));
        }
        return List.copyOf(candidates);
    }

    private Digest32 lookup(UUID customerId, String appId, String installationId,
                            String keyId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(lookupKeys.key(keyId), "HmacSHA256"));
            return Digest32.fromBytes(mac.doFinal(encode(
                    "BANK_DEVICE_ID_LOOKUP_V1", customerId.toString(), appId, installationId)));
        } catch (GeneralSecurityException failure) {
            throw new InvalidDeviceIdProtectionException(failure);
        }
    }

    private static byte[] aad(UUID customerId, String appId, UUID bindingId) {
        return encode("BANK_DEVICE_ID_CIPHERTEXT_V1", customerId.toString(),
                appId, bindingId.toString());
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

    private static void requireIdentity(UUID customerId, String appId, String installationId) {
        Objects.requireNonNull(customerId);
        if (appId == null || appId.isBlank() || appId.length() > 64
                || installationId == null || installationId.length() < 16
                || installationId.length() > 300) {
            throw new InvalidDeviceIdProtectionException();
        }
        utf8(appId);
        utf8(installationId);
    }
}
