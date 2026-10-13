package com.vpbank.dcp.infrastructure.adapter.out.totp;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-GCM storage envelope bound to the exact credential and trusted-device owner. */
public final class TotpSecretCodec {
    private static final byte VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final int SECRET_BYTES = 20;
    private static final int TAG_BITS = 128;

    private final TotpSecretKeys keys;
    private final SecureRandom random;

    public TotpSecretCodec(TotpSecretKeys keys, SecureRandom random) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.random = Objects.requireNonNull(random, "random");
    }

    public ProtectedTotpSecret protect(UUID customerId, String channel, UUID bindingId,
                                       UUID credentialId, byte[] secret) {
        requireContext(customerId, channel, bindingId, credentialId);
        if (secret == null || secret.length != SECRET_BYTES) {
            throw new InvalidTotpSecretException();
        }
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        String keyId = keys.activeKeyId();
        byte[] key = keys.key(keyId);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(customerId, channel, bindingId, credentialId));
            byte[] encrypted = cipher.doFinal(secret);
            byte[] envelope = ByteBuffer.allocate(1 + NONCE_BYTES + encrypted.length)
                    .put(VERSION).put(nonce).put(encrypted).array();
            return new ProtectedTotpSecret(keyId, envelope);
        } catch (GeneralSecurityException failure) {
            throw new InvalidTotpSecretException(failure);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    public byte[] reveal(UUID customerId, String channel, UUID bindingId,
                         UUID credentialId, ProtectedTotpSecret protectedSecret) {
        requireContext(customerId, channel, bindingId, credentialId);
        Objects.requireNonNull(protectedSecret, "protectedSecret");
        byte[] envelope = protectedSecret.ciphertext();
        if (envelope.length != 1 + NONCE_BYTES + SECRET_BYTES + TAG_BITS / 8
                || envelope[0] != VERSION) {
            throw new InvalidTotpSecretException();
        }
        byte[] nonce = Arrays.copyOfRange(envelope, 1, 1 + NONCE_BYTES);
        byte[] key = keys.key(protectedSecret.keyId());
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(customerId, channel, bindingId, credentialId));
            return cipher.doFinal(envelope, 1 + NONCE_BYTES,
                    envelope.length - 1 - NONCE_BYTES);
        } catch (GeneralSecurityException failure) {
            throw new InvalidTotpSecretException(failure);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(envelope, (byte) 0);
        }
    }

    private static byte[] aad(UUID customerId, String channel, UUID bindingId,
                              UUID credentialId) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (String field : new String[] {"BANK_DEVICE_TOTP_SECRET_V1", customerId.toString(),
                channel, bindingId.toString(), credentialId.toString()}) {
            byte[] value = field.getBytes(StandardCharsets.UTF_8);
            bytes.writeBytes(ByteBuffer.allocate(4).putInt(value.length).array());
            bytes.writeBytes(value);
        }
        return bytes.toByteArray();
    }

    private static void requireContext(UUID customerId, String channel, UUID bindingId,
                                       UUID credentialId) {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(credentialId, "credentialId");
        if (channel == null || channel.isBlank() || channel.length() > 64) {
            throw new InvalidTotpSecretException();
        }
    }
}
