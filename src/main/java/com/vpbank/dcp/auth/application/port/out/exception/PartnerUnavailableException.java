package com.vpbank.dcp.auth.application.port.out.exception;

/**
 * A partner (Customer, Keycloak, Notification) did not answer, answered with an error, or the
 * outcome of the call is unknown. Registration reports UNAVAILABLE and does not retry.
 */
public final class PartnerUnavailableException extends RuntimeException {
    public PartnerUnavailableException(String partner, Throwable cause) {
        super(partner + " is unavailable", cause);
    }

    public PartnerUnavailableException(String partner) {
        super(partner + " is unavailable");
    }
}
