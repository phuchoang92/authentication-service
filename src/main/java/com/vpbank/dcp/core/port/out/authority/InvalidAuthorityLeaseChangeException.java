package com.vpbank.dcp.core.port.out.authority;

public final class InvalidAuthorityLeaseChangeException extends RuntimeException {

    public InvalidAuthorityLeaseChangeException() {
        super("Authority lease change is invalid");
    }
}
