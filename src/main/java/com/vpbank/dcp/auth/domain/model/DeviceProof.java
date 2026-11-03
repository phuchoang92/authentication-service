package com.vpbank.dcp.auth.domain.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * What a trusted device signs at login to prove it still holds its key (slice 13): the moment it signed,
 * a nonce it never reuses, and the raw signature over the login's bound fields. The bytes are the
 * app's; whether they verify under the stored key is the verifier's answer.
 */
public record DeviceProof(Instant issuedAt, String nonce, byte[] signature) {
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9_-]{16,64}");
    private static final int MAX_SIGNATURE_LENGTH = 8192;

    public DeviceProof {
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(signature, "signature");
        if (!NONCE.matcher(nonce).matches()) {
            throw new IllegalArgumentException("A proof nonce is 16 to 64 base64url characters");
        }
        if (signature.length == 0 || signature.length > MAX_SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("A proof signature is 1 to " + MAX_SIGNATURE_LENGTH + " bytes");
        }
        signature = signature.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof DeviceProof that && issuedAt.equals(that.issuedAt) && nonce.equals(that.nonce)
                && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuedAt, nonce, Arrays.hashCode(signature));
    }

    @Override
    public String toString() {
        return "DeviceProof[issuedAt=" + issuedAt + ", nonce=" + nonce + ", redacted]";
    }
}
