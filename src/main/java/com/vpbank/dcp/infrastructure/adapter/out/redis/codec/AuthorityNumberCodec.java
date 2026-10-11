package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

final class AuthorityNumberCodec {

    private AuthorityNumberCodec() {
    }

    static long decode(String value) {
        if (value == null || !value.matches("[0-9]{1,16}")) {
            throw new InvalidAuthorityValueException();
        }
        try {
            long parsed = Long.parseLong(value);
            if (parsed > 9007199254740991L) {
                throw new InvalidAuthorityValueException();
            }
            return parsed;
        } catch (NumberFormatException failure) {
            throw new InvalidAuthorityValueException(failure);
        }
    }

    static String encode(long value) {
        if (value < 0 || value > 9007199254740991L) {
            throw new InvalidAuthorityValueException();
        }
        return Long.toString(value);
    }
}
