package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

/**
 * A request passed Bean Validation but a value object still refused it (the formats drifted).
 * Mapped to 400 REQUEST_REJECTED; the message names the rule, never the value.
 */
public final class InvalidRequestException extends RuntimeException {
    public InvalidRequestException(String message) {
        super(message);
    }
}
