package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.core.port.out.customer.CustomerResolution;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;
import java.util.Objects;

/** Translates the assumed Customer contract into the core-owned directory port. */
public final class CustomerDirectoryAdapter implements CustomerDirectory {

    private final CustomerHttpClient client;

    public CustomerDirectoryAdapter(CustomerHttpClient client) {
        this.client = Objects.requireNonNull(client, "client");
    }

    @Override
    public CustomerResolution resolve(VerifiedProviderIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        CustomerHttpClient.ResolveCustomerRequest request = new CustomerHttpClient.ResolveCustomerRequest(
                new CustomerHttpClient.ProviderIdentity(identity.issuer(), identity.subject()));
        try {
            ExternalHttpClient.Response<CustomerResponse, CustomerErrorResponse> reply = client.resolve(request);
            if (reply.isSuccess()) {
                return new CustomerResolution.Found(CustomerResponseMapper.fromResolve(reply.successBody()));
            }
            if (reply.status() == 404 && isCustomerNotFound(reply.errorBody())) {
                return new CustomerResolution.NotFound();
            }
            throw new CustomerDirectoryUnavailableException();
        } catch (ExternalHttpRequestFailedException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    @Override
    public CustomerAuthenticationState currentStatus(CustomerNumber customerNumber) {
        String customerId = customerNumber.value();
        if (!CustomerHttpEndpoints.isValidCustomerId(customerId)) {
            throw new CustomerDirectoryUnavailableException();
        }
        try {
            ExternalHttpClient.Response<CustomerResponse, CustomerErrorResponse> reply =
                    client.currentStatus(customerId);
            if (!reply.isSuccess()) {
                throw new CustomerDirectoryUnavailableException();
            }
            return CustomerResponseMapper.fromStatus(customerId, reply.successBody());
        } catch (ExternalHttpRequestFailedException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    private static boolean isCustomerNotFound(CustomerErrorResponse error) {
        return "CUSTOMER_NOT_FOUND".equals(error.code()) && error.correlationId() != null
                && !error.correlationId().isBlank() && error.correlationId().length() <= 128;
    }
}
