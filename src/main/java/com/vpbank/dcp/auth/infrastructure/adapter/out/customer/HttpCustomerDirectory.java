package com.vpbank.dcp.auth.infrastructure.adapter.out.customer;

import com.vpbank.dcp.auth.core.customer.CustomerDirectory;
import com.vpbank.dcp.auth.core.customer.CustomerProfile;
import com.vpbank.dcp.auth.core.customer.PartnerUnavailableException;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Objects;
import java.util.Optional;

/**
 * Customer service profile lookup: {@code GET <profilePath>} with the customer ID. 200 is a
 * profile, 404 is "unknown customer", anything else (or a profile for another customer) is
 * unavailable.
 */
public final class HttpCustomerDirectory implements CustomerDirectory {
    private static final String PARTNER = "Customer service";

    private final RestClient client;
    private final String profilePath;
    private final String serviceToken;

    /** {@code profilePath} has one {@code {customerId}} variable; {@code serviceToken} may be null. */
    public HttpCustomerDirectory(RestClient client, String profilePath, String serviceToken) {
        this.client = Objects.requireNonNull(client);
        this.profilePath = Objects.requireNonNull(profilePath);
        this.serviceToken = serviceToken;
    }

    @Override
    public Optional<CustomerProfile> profile(String customerId) {
        Objects.requireNonNull(customerId, "customerId");
        try {
            return client.get().uri(profilePath, customerId)
                    .accept(MediaType.APPLICATION_JSON)
                    .headers(headers -> {
                        if (serviceToken != null) {
                            headers.setBearerAuth(serviceToken);
                        }
                    })
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status == 404) {
                            return Optional.<CustomerProfile>empty();
                        }
                        if (status != 200) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        ProfileResponse body = response.bodyTo(ProfileResponse.class);
                        if (body == null || !customerId.equals(body.customerId())) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        return Optional.of(new CustomerProfile(customerId, "ELIGIBLE".equals(body.status()),
                                body.phone(), Boolean.TRUE.equals(body.phoneVerified()), body.email(),
                                Boolean.TRUE.equals(body.emailVerified())));
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }

    record ProfileResponse(String customerId, String status, String phone, Boolean phoneVerified,
                           String email, Boolean emailVerified) { }
}
