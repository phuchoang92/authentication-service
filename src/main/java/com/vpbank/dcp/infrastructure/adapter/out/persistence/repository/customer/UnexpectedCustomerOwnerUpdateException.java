package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.customer;

final class UnexpectedCustomerOwnerUpdateException extends RuntimeException {

    UnexpectedCustomerOwnerUpdateException() {
        super("Customer owner persistence invariant failed");
    }
}
