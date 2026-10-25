package com.vpbank.dcp.core.customer;

public enum CustomerStatus {
    ELIGIBLE,
    BLOCKED,
    CLOSED;

    public boolean allowsLogin() {
        return this == ELIGIBLE;
    }
}
