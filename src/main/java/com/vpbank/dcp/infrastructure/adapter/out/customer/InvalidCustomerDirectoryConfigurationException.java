package com.vpbank.dcp.infrastructure.adapter.out.customer;

public final class InvalidCustomerDirectoryConfigurationException extends RuntimeException {

    public InvalidCustomerDirectoryConfigurationException() {
        super("Invalid Customer directory configuration");
    }
}
