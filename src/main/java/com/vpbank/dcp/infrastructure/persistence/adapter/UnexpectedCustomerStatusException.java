package com.vpbank.dcp.infrastructure.persistence.adapter;

public final class UnexpectedCustomerStatusException extends RuntimeException {
    public UnexpectedCustomerStatusException() {
        super("Customer storage contains an unsupported status");
    }
}
