package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.security.Digest32;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public final class Sha256Digests {

    public Digest32 ofProofId(String exactJti) {
        Objects.requireNonNull(exactJti, "exactJti");
        if (exactJti.isEmpty() || !StandardCharsets.UTF_8.newEncoder().canEncode(exactJti)) {
            throw new InvalidCryptographicInputException();
        }
        byte[] encoded = exactJti.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 256) {
            throw new InvalidCryptographicInputException();
        }
        return sha256(encoded);
    }

    public Digest32 ofToken(String exactToken) {
        Objects.requireNonNull(exactToken, "exactToken");
        if (!StandardCharsets.US_ASCII.newEncoder().canEncode(exactToken)) {
            throw new InvalidCryptographicInputException();
        }
        return sha256(exactToken.getBytes(StandardCharsets.US_ASCII));
    }

    public Digest32 sha256(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        try {
            return Digest32.fromBytes(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException failure) {
            throw new CryptographicProviderUnavailableException(failure);
        }
    }
}
