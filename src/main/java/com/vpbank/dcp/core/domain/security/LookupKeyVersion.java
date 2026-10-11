package com.vpbank.dcp.core.domain.security;

import java.util.Objects;

public record LookupKeyVersion(String value) {

    public LookupKeyVersion {
        Objects.requireNonNull(value, "value");
        if (!value.matches("[A-Za-z0-9_-]{1,16}")) {
            throw new InvalidKeyIdentifierException();
        }
    }
}
