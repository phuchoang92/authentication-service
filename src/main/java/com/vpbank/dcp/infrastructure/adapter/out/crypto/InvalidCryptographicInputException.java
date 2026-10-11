package com.vpbank.dcp.infrastructure.adapter.out.crypto;

public final class InvalidCryptographicInputException extends IllegalArgumentException {

    public InvalidCryptographicInputException() {
        super("Cryptographic input is invalid");
    }

    public InvalidCryptographicInputException(Throwable cause) {
        super("Cryptographic input is invalid", cause);
    }
}
