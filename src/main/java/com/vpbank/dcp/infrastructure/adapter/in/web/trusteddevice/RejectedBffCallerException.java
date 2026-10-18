package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

/** The BFF assertion is missing, malformed, unverifiable or already used. */
public final class RejectedBffCallerException extends RuntimeException {
    public RejectedBffCallerException() {
        super("The caller was rejected");
    }

    public RejectedBffCallerException(Throwable cause) {
        super("The caller was rejected", cause);
    }
}
