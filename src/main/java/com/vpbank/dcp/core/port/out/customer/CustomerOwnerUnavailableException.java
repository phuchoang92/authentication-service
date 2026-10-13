package com.vpbank.dcp.core.port.out.customer;

import java.util.Objects;

public final class CustomerOwnerUnavailableException extends RuntimeException {
    public CustomerOwnerUnavailableException(Throwable cause) {
        super("Customer owner storage is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
