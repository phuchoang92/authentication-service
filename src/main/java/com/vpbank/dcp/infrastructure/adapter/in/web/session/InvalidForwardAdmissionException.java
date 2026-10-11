package com.vpbank.dcp.infrastructure.adapter.in.web.session;

public final class InvalidForwardAdmissionException extends RuntimeException {
    public InvalidForwardAdmissionException() {
        super("The banking request was rejected");
    }
}
