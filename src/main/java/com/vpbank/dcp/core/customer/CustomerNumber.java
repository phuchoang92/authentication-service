package com.vpbank.dcp.core.customer;

/**
 * The Customer domain's own business identifier, as returned by the Customer service.
 *
 * <p>Distinct from {@link SubjectId}, which is Auth's internal owner id. Previously both were
 * called {@code customerId}, and this one was also called {@code customerExternalId}.
 */
public record CustomerNumber(String value) {

    public CustomerNumber {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new InvalidCustomerStateException();
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
