package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.infrastructure.persistence.repository.InvalidSessionPersistenceException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import tools.jackson.databind.json.JsonMapper;

/** Preserves the escrow JSON bytes and verifies their SHA-256 before decoding. */
public final class SessionDeliveryEscrowCodec {
    private final JsonMapper json;

    public SessionDeliveryEscrowCodec(JsonMapper json) {
        this.json = Objects.requireNonNull(json);
    }

    public byte[] encode(EscrowedSessionDelivery delivery) {
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

    public EscrowedSessionDelivery decode(byte[] protectedResult, Digest32 expectedDigest) {
        if (protectedResult == null || !digest(protectedResult).equals(expectedDigest)) {
            throw new InvalidSessionPersistenceException();
        }
        return json.readValue(protectedResult, EscrowedSessionDelivery.class);
    }
}
