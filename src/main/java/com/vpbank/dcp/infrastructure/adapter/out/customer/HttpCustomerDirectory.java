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
            return readCustomerResponse(http.postJson(CustomerHttpEndpoints.RESOLVE,
                    request, CustomerResponse.class));
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
            String path = CustomerHttpEndpoints.status(customerId);
            CustomerAuthenticationState state = readCustomerResponse(
                    http.get(path, CustomerResponse.class));
            if (!customerId.equals(state.customerId())) {
                throw new CustomerDirectoryUnavailableException();
            }
            return state;
        } catch (ExternalHttpRequestFailedException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    private CustomerAuthenticationState readCustomerResponse(
            ExternalHttpClient.Response<CustomerResponse> response) {
        if (response.status() != 200) {
            throw new CustomerDirectoryUnavailableException();
        }
        return toCustomerState(response.body());
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
            return new ResolveCustomerRequest(
                    new ProviderIdentity(identity.issuer(), identity.subject()));
        }
    }

    private record CustomerResponse(String customerId, String status, Long statusVersion,
                                    Long lastAccessBlockVersion, String checkedAt) {
    }
}
