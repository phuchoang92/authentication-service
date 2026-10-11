package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import java.util.Objects;

/** Sends Customer requests; does not interpret eligibility or provider error codes. */
public final class CustomerHttpClient {

    private final ExternalHttpClient http;

    public CustomerHttpClient(ExternalHttpClient http) {
        this.http = Objects.requireNonNull(http, "http");
    }

    ExternalHttpClient.Response<CustomerResponse, CustomerErrorResponse> resolve(
            ResolveCustomerRequest request) {
        return http.postJson(CustomerHttpEndpoints.RESOLVE, request);
    }

    ExternalHttpClient.Response<CustomerResponse, CustomerErrorResponse> currentStatus(
            String customerId) {
        return http.getJson(CustomerHttpEndpoints.STATUS.bindSegment("customerId", customerId));
    }

    record ResolveCustomerRequest(ProviderIdentity identity) {
        @Override
        public String toString() {
            return "ResolveCustomerRequest[redacted]";
        }
    }

    record ProviderIdentity(String issuer, String subject) {
        @Override
        public String toString() {
            return "ProviderIdentity[redacted]";
        }
    }
}
