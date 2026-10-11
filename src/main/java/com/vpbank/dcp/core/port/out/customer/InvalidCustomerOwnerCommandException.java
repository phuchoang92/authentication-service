package com.vpbank.dcp.core.port.out.customer;

public final class InvalidCustomerOwnerCommandException extends IllegalArgumentException {

    public InvalidCustomerOwnerCommandException() {
        super("Invalid Customer owner acceptance command");
    }
}
