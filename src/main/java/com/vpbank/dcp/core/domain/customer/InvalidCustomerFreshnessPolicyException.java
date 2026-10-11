package com.vpbank.dcp.core.domain.customer;

public final class InvalidCustomerFreshnessPolicyException extends IllegalArgumentException {

    public InvalidCustomerFreshnessPolicyException() {
        super("Customer snapshot freshness policy must be positive");
    }
}
