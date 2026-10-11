package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalPath;
import java.util.Set;
import java.util.regex.Pattern;

/** Paths accepted from the assumed Customer Service HTTP contract. */
public final class CustomerHttpEndpoints {

    static final String RESOLVE = "/internal/v1/customer-authentication/resolve";
    private static final String STATUS_PREFIX = "/internal/v1/customers/";
    private static final String STATUS_SUFFIX = "/authentication-status";
    private static final Pattern CUSTOMER_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final Pattern STATUS_ROUTE = Pattern.compile(
            "/internal/v1/customers/[A-Za-z0-9._%-]{1,384}/authentication-status");

    private CustomerHttpEndpoints() {
    }

    public static boolean isValidCustomerId(String customerId) {
        return customerId != null && CUSTOMER_ID.matcher(customerId).matches();
    }

    public static String status(String customerId) {
        return STATUS_PREFIX + ExternalPath.segment(customerId) + STATUS_SUFFIX;
    }

    public static Set<ExternalHttpSettings.Route> allowedRoutes() {
        return Set.of(ExternalHttpSettings.Route.exact("POST", RESOLVE),
                new ExternalHttpSettings.Route("GET", STATUS_ROUTE));
    }
}
