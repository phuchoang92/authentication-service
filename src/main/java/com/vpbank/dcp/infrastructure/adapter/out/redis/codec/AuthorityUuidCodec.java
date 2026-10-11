package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

import java.util.UUID;

final class AuthorityUuidCodec {

    private AuthorityUuidCodec() {
    }

    static UUID decode(String value) {
        try {
            UUID id = UUID.fromString(value);
            if (!id.toString().equals(value)) {
                throw new InvalidAuthorityValueException();
            }
            return id;
        } catch (NullPointerException | IllegalArgumentException failure) {
            throw new InvalidAuthorityValueException(failure);
        }
    }
}
