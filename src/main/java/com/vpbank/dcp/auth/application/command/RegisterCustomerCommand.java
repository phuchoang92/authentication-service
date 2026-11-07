package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.Builder;
import lombok.NonNull;

/**
 * What the Customer service asks for when onboarding ends. Formats were checked when the value
 * objects were built; {@code email} is optional and only used when the realm needs it.
 */
@Builder
public record RegisterCustomerCommand(@NonNull CustomerId customerId,
                                      @NonNull UserName userName,
                                      @NonNull String firstName,
                                      @NonNull String lastName,
                                      @NonNull PhoneNumber phoneNumber,
                                      Email email) {
    @Override
    public String toString() {
        return "RegisterCustomerCommand[customerId=" + customerId + ", redacted]";
    }
}
