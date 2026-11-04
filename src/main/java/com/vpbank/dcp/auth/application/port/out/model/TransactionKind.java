package com.vpbank.dcp.auth.application.port.out.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * What kind of transaction a flow keeps in the cache: a purpose code, which becomes part of the key so flows
 * never read each other's records, and the payload type the store must decode. A flow declares one as a
 * constant; the store knows nothing else about the flow.
 */
public record TransactionKind<P>(String purpose, Class<P> payloadType) {
    private static final Pattern PURPOSE = Pattern.compile("[a-z0-9-]{1,32}");

    public TransactionKind {
        Objects.requireNonNull(purpose, "purpose");
        Objects.requireNonNull(payloadType, "payloadType");
        if (!PURPOSE.matcher(purpose).matches()) {
            throw new IllegalArgumentException("A purpose is 1-32 lower-case letters, digits or dashes");
        }
    }
}
