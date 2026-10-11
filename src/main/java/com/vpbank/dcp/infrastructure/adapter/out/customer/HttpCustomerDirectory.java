package com.vpbank.dcp.infrastructure.adapter.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.http.BoundedJsonExchange;
import com.vpbank.dcp.infrastructure.adapter.out.http.PartnerHttpFailureException;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * mTLS-backed adapter for the assumed Customer authentication contract.
 */
public final class HttpCustomerDirectory implements CustomerDirectory {

    private static final int MAX_RESPONSE_BYTES = 4096;
    private static final String RESOLVE_PATH = "/internal/v1/customer-authentication/resolve";
    private static final String STATUS_PREFIX = "/internal/v1/customers/";
    private static final String STATUS_SUFFIX = "/authentication-status";

    private final BoundedJsonExchange exchange;
    private final URI origin;
    private final Duration timeout;
    private final JsonMapper json;

    public HttpCustomerDirectory(HttpClient client, URI origin, Duration timeout, JsonMapper json) {
        this.origin = checkedOrigin(origin);
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.json = Objects.requireNonNull(json, "json");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new InvalidCustomerDirectoryConfigurationException();
        }
        this.exchange = new BoundedJsonExchange(client, origin, timeout, MAX_RESPONSE_BYTES,
                Set.of(BoundedJsonExchange.AllowedEndpoint.exact("POST", RESOLVE_PATH),
                        new BoundedJsonExchange.AllowedEndpoint("GET", Pattern.compile(
                                "/internal/v1/customers/[A-Za-z0-9._%-]{1,384}/authentication-status"))));
    }

    @Override
    public CustomerAuthenticationState resolve(VerifiedProviderIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        try {
            String body = json.writeValueAsString(new ResolveRequest(
                    new Identity(identity.issuer(), identity.subject())));
            HttpRequest request = request(RESOLVE_PATH).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            return execute(request);
        } catch (RuntimeException failure) {
            if (failure instanceof CustomerDirectoryUnavailableException unavailable) {
                throw unavailable;
            }
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    @Override
    public CustomerAuthenticationState currentStatus(String customerId) {
        if (customerId == null || !customerId.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new CustomerDirectoryUnavailableException();
        }
        String path = STATUS_PREFIX + URLEncoder.encode(customerId, StandardCharsets.UTF_8)
                + STATUS_SUFFIX;
        CustomerAuthenticationState state = execute(request(path).GET().build());
        if (!customerId.equals(state.customerId())) {
            throw new CustomerDirectoryUnavailableException();
        }
        return state;
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(origin.resolve(path))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Accept-Encoding", "identity");
    }

    private CustomerAuthenticationState execute(HttpRequest request) {
        try {
            BoundedJsonExchange.JsonResponse response = exchange.send(request);
            if (response.status() != 200) {
                throw new CustomerDirectoryUnavailableException();
            }
            return decode(response.body());
        } catch (PartnerHttpFailureException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    CustomerAuthenticationState decode(String response) {
        try {
            CustomerReply reply = json.readValue(response, CustomerReply.class);
            if (reply == null || reply.checkedAt() == null || !reply.checkedAt().endsWith("Z")
                    || reply.statusVersion() == null || reply.lastAccessBlockVersion() == null) {
                throw new CustomerDirectoryUnavailableException();
            }
            return new CustomerAuthenticationState(reply.customerId(),
                    CustomerStatus.valueOf(reply.status()), reply.statusVersion(),
                    reply.lastAccessBlockVersion(), Instant.parse(reply.checkedAt()));
        } catch (RuntimeException failure) {
            throw new CustomerDirectoryUnavailableException(failure);
        }
    }

    private static URI checkedOrigin(URI origin) {
        Objects.requireNonNull(origin, "origin");
        if (!"https".equals(origin.getScheme()) || origin.getHost() == null
                || origin.getUserInfo() != null || origin.getRawQuery() != null
                || origin.getRawFragment() != null
                || !("".equals(origin.getRawPath()) || "/".equals(origin.getRawPath()))) {
            throw new InvalidCustomerDirectoryConfigurationException();
        }
        return origin;
    }

    private record Identity(String issuer, String subject) {
    }

    private record ResolveRequest(Identity identity) {
    }

    private record CustomerReply(String customerId, String status, Long statusVersion,
                                 Long lastAccessBlockVersion, String checkedAt) {
    }
}
