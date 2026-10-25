package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;

import java.util.Objects;

/**
 * What the Customer service asks for when onboarding ends. Formats were checked when the value
 * objects were built; {@code email} is optional and only used when the realm needs it.
 */
@Builder
public record RegisterCustomerCommand(CustomerId customerId, UserName userName, String firstName,
                                      String lastName, PhoneNumber phoneNumber, Email email) {
    public RegisterCustomerCommand {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(firstName, "firstName");
        Objects.requireNonNull(lastName, "lastName");
        Objects.requireNonNull(phoneNumber, "phoneNumber");
    }

    @Override
    public String toString() {
        return "RegisterCustomerCommand[customerId=" + customerId + ", redacted]";
    }
}
