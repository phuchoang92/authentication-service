package com.vpbank.dcp.infrastructure.adapter.out.http;

public final class PartnerHttpFailureException extends RuntimeException {

    public PartnerHttpFailureException() {
        super("Partner HTTP exchange failed");
    }

    public PartnerHttpFailureException(Throwable cause) {
        super("Partner HTTP exchange failed", cause);
    }
}
