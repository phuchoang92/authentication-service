package com.vpbank.dcp.auth.application.port.out.exception;

/** The app's token-encryption key is not an acceptable public P-256 JWK. A request error, not an outage. */
public final class InvalidEncryptionKeyException extends RuntimeException {
    public InvalidEncryptionKeyException(String message) {
        super(message);
    }
}
