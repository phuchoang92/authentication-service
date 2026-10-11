package com.vpbank.dcp.infrastructure.adapter.out.persistence.customer;

final class UnexpectedCustomerOwnerUpdateException extends RuntimeException {

    UnexpectedCustomerOwnerUpdateException() {
        super("Customer owner persistence invariant failed");
    }
}
