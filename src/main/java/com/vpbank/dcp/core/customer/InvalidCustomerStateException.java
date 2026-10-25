package com.vpbank.dcp.core.customer;

public final class InvalidCustomerStateException extends RuntimeException {

    public InvalidCustomerStateException() {
        super("Invalid Customer authentication state");
    }
}
