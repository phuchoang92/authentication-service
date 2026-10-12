package com.vpbank.dcp.infrastructure.adapter.in.web.session;

public final class InvalidBankingAdmissionRequestException extends RuntimeException {
    public InvalidBankingAdmissionRequestException() {
        super("The banking request was rejected");
    }
}
