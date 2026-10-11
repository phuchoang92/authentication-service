package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.InvalidCustomerStateException;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/** Validates the assumed Customer wire response before it crosses the core boundary. */
final class CustomerResponseMapper {

    private CustomerResponseMapper() {
    }

    static CustomerAuthenticationState fromResolve(CustomerResponse response) {
        return toState(response);
    }

    static CustomerAuthenticationState fromStatus(String requestedCustomerId,
                                                  CustomerResponse response) {
        CustomerAuthenticationState state = toState(response);
        if (!state.customerId().equals(requestedCustomerId)) {
            throw new CustomerDirectoryUnavailableException();
        }
        return state;
    }

    private static CustomerAuthenticationState toState(CustomerResponse response) {
        if (response == null || response.customerId() == null || response.status() == null
                || response.statusVersion() == null || response.lastAccessBlockVersion() == null
                || response.checkedAt() == null || !response.checkedAt().endsWith("Z")) {
            throw new CustomerDirectoryUnavailableException();
        }
        try {
            return new CustomerAuthenticationState(response.customerId(),
                    status(response.status()), response.statusVersion(),
                    response.lastAccessBlockVersion(), Instant.parse(response.checkedAt()));
        } catch (InvalidCustomerStateException | DateTimeParseException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    private static CustomerStatus status(String wireCode) {
        return switch (wireCode) {
            case "ELIGIBLE" -> CustomerStatus.ELIGIBLE;
            case "BLOCKED" -> CustomerStatus.BLOCKED;
            case "CLOSED" -> CustomerStatus.CLOSED;
            default -> throw new CustomerDirectoryUnavailableException();
        };
    }
}
