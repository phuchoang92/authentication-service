package com.vpbank.dcp.core.port.out.customer;

public final class CustomerDirectoryUnavailableException extends RuntimeException {

    public CustomerDirectoryUnavailableException() {
        super("Customer authentication status is unavailable");
    }

    public CustomerDirectoryUnavailableException(Throwable cause) {
        super("Customer authentication status is unavailable", cause);
    }
}
