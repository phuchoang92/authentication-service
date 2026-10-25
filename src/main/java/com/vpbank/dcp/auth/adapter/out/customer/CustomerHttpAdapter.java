package com.vpbank.dcp.auth.adapter.out.customer;

import com.vpbank.dcp.auth.adapter.out.customer.dto.CustomerProfileDto;
import com.vpbank.dcp.auth.adapter.out.customer.mapper.CustomerProfileMapper;
import com.vpbank.dcp.auth.application.port.out.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.CustomerProfile;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public final class CustomerHttpAdapter implements CustomerDirectoryPort {
    private static final String PARTNER = "Customer service";

    @NonNull private final RestClient client;
    /** Has one {@code {customerId}} variable. */
    @NonNull private final String profilePath;
    /** May be null: no bearer header is sent. */
    private final String serviceToken;

    @Override
    public Optional<CustomerProfile> profile(CustomerId customerId) {
        Objects.requireNonNull(customerId, "customerId");
        try {
            return client.get().uri(profilePath, customerId.value())
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
                        CustomerProfileDto body = response.bodyTo(CustomerProfileDto.class);
                        if (body == null || !customerId.value().equals(body.customerId())) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        return Optional.of(CustomerProfileMapper.toProfile(customerId, body));
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
