package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.InvalidCustomerStateException;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;

/**
 * mTLS-backed adapter for the assumed Customer authentication contract.
 */
public final class HttpCustomerDirectory implements CustomerDirectory {

    private final ExternalHttpClient http;

    public HttpCustomerDirectory(ExternalHttpClient http) {
        this.http = Objects.requireNonNull(http, "http");
    }

    @Override
    public CustomerAuthenticationState resolve(VerifiedProviderIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        try {
            ResolveCustomerRequest request = ResolveCustomerRequest.from(identity);
            CustomerResponse response = http.postJson(CustomerHttpEndpoints.RESOLVE, request).body();
            return toCustomerState(response);
        } catch (ExternalHttpRequestFailedException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    @Override
    public CustomerAuthenticationState currentStatus(String customerId) {
        if (!CustomerHttpEndpoints.isValidCustomerId(customerId)) {
            throw new CustomerDirectoryUnavailableException();
        }
        try {
            CustomerResponse response = http.getJson(CustomerHttpEndpoints.STATUS
                    .bindSegment("customerId", customerId)).body();
            CustomerAuthenticationState state = toCustomerState(response);
            if (!customerId.equals(state.customerId())) {
                throw new CustomerDirectoryUnavailableException();
            }
            return state;
        } catch (ExternalHttpRequestFailedException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    private CustomerAuthenticationState toCustomerState(CustomerResponse reply) {
        if (reply.customerId() == null || reply.status() == null || reply.checkedAt() == null
                || !reply.checkedAt().endsWith("Z") || reply.statusVersion() == null
                || reply.lastAccessBlockVersion() == null) {
            throw new CustomerDirectoryUnavailableException();
        }
        try {
            return new CustomerAuthenticationState(reply.customerId(),
                    CustomerStatus.valueOf(reply.status()), reply.statusVersion(),
                    reply.lastAccessBlockVersion(), Instant.parse(reply.checkedAt()));
        } catch (IllegalArgumentException | DateTimeParseException
                 | InvalidCustomerStateException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    private record ProviderIdentity(String issuer, String subject) {
    }

    private record ResolveCustomerRequest(ProviderIdentity identity) {
        private static ResolveCustomerRequest from(VerifiedProviderIdentity identity) {
            return new ResolveCustomerRequest(new ProviderIdentity(identity.issuer(), identity.subject()));
        }
    }
}
