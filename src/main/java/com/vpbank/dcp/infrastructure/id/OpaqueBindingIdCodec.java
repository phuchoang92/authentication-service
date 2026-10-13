package com.vpbank.dcp.infrastructure.id;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/** An issued random 128-bit ID is exposed as an opaque URL-safe value, never UUID text. */
public final class OpaqueBindingIdCodec {
    public String encode(UUID id) {
        ByteBuffer bytes = ByteBuffer.allocate(16).putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.array());
    }

    public Optional<UUID> decode(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{22}")) {
            return Optional.empty();
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(value);
            if (bytes.length != 16) {
                return Optional.empty();
            }
            ByteBuffer decoded = ByteBuffer.wrap(bytes);
            UUID id = new UUID(decoded.getLong(), decoded.getLong());
            return encode(id).equals(value) ? Optional.of(id) : Optional.empty();
        } catch (IllegalArgumentException failure) {
            return Optional.empty();
        }
    }
}
