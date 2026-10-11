package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import java.util.Set;
import java.util.regex.Pattern;

/** Paths accepted from the assumed Customer Service HTTP contract. */
public final class CustomerHttpEndpoints {

    static final ExternalEndpoint<CustomerResponse> RESOLVE = ExternalEndpoint.postJson(
            "/internal/v1/customer-authentication/resolve", CustomerResponse.class, Set.of(200));
    static final ExternalEndpoint<CustomerResponse> STATUS = ExternalEndpoint.getJson(
            "/internal/v1/customers/{customerId}/authentication-status",
            CustomerResponse.class, Set.of(200));
    private static final Pattern CUSTOMER_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

    private CustomerHttpEndpoints() {
    }

    public static boolean isValidCustomerId(String customerId) {
        return customerId != null && CUSTOMER_ID.matcher(customerId).matches();
    }

    public static Set<ExternalHttpSettings.Route> allowedRoutes() {
        return Set.of(RESOLVE.route(), STATUS.route());
    }
}
