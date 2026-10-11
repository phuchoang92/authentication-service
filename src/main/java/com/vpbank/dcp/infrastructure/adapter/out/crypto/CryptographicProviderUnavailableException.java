package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.util.Objects;

public final class CryptographicProviderUnavailableException extends RuntimeException {

    public CryptographicProviderUnavailableException(Throwable cause) {
        super("Required cryptographic provider is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
