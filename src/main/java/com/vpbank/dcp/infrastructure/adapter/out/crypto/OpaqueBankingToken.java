package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.util.Objects;

/** A client credential. It must never be logged or embedded in exception messages. */
public final class OpaqueBankingToken {

    private final String value;

    OpaqueBankingToken(String value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    public String exactValue() {
        return value;
    }

    @Override
    public String toString() {
        return "OpaqueBankingToken[redacted]";
    }
}
