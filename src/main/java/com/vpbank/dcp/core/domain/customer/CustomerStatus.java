package com.vpbank.dcp.core.domain.customer;

public enum CustomerStatus {
    ELIGIBLE,
    BLOCKED,
    CLOSED;

    public boolean allowsLogin() {
        return this == ELIGIBLE;
    }
}
