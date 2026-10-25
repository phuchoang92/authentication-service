package com.vpbank.dcp.auth.core.customer;

import java.util.Objects;

/**
 * What the Customer service asks for when onboarding ends. Field formats are checked at the
 * HTTP boundary; {@code email} is optional and only used when the realm needs it.
 */
public record RegistrationCommand(String customerId, String userName, String firstName,
                                  String lastName, String phoneNumber, String email) {
    public RegistrationCommand {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(firstName, "firstName");
        Objects.requireNonNull(lastName, "lastName");
        Objects.requireNonNull(phoneNumber, "phoneNumber");
    }

    @Override
    public String toString() {
        return "RegistrationCommand[customerId=" + customerId + ", redacted]";
    }
}
