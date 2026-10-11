package com.vpbank.dcp.infrastructure.adapter.out.crypto;

public final class InvalidPasswordHmacKeyException extends IllegalStateException {

    public InvalidPasswordHmacKeyException() {
        super("Password command HMAC key is unavailable or invalid");
    }
}
