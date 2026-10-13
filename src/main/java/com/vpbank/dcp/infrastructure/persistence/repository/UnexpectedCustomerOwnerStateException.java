package com.vpbank.dcp.infrastructure.persistence.repository;

public final class UnexpectedCustomerOwnerStateException extends RuntimeException {
    public UnexpectedCustomerOwnerStateException() {
        super("Customer owner storage returned an inconsistent result");
    }
}
