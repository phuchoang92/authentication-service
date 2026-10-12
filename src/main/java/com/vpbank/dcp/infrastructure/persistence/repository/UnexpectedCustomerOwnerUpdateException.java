package com.vpbank.dcp.infrastructure.persistence.repository;

final class UnexpectedCustomerOwnerUpdateException extends RuntimeException {

    UnexpectedCustomerOwnerUpdateException() {
        super("Customer owner persistence invariant failed");
    }
}
