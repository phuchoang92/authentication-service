package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.infrastructure.persistence.repository.InvalidPasswordSessionPersistenceException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import tools.jackson.databind.json.JsonMapper;

/** Preserves the escrow JSON bytes and verifies their SHA-256 before decoding. */
public final class PasswordDeliveryEscrowCodec {
    private final JsonMapper json;

    public PasswordDeliveryEscrowCodec(JsonMapper json) {
        this.json = Objects.requireNonNull(json);
    }

    public byte[] encode(EscrowedPasswordDelivery delivery) {
        return json.writeValueAsBytes(Objects.requireNonNull(delivery));
    }

    public Digest32 digest(byte[] protectedResult) {
        try {
            return Digest32.fromBytes(MessageDigest.getInstance("SHA-256")
                    .digest(Objects.requireNonNull(protectedResult)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }

    public EscrowedPasswordDelivery decode(byte[] protectedResult, Digest32 expectedDigest) {
        if (protectedResult == null || !digest(protectedResult).equals(expectedDigest)) {
            throw new InvalidPasswordSessionPersistenceException();
        }
        return json.readValue(protectedResult, EscrowedPasswordDelivery.class);
    }
}
