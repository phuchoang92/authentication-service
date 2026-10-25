package com.vpbank.dcp.auth.infrastructure.adapter.out.customer;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.customer.dto.CustomerProfileDto;
import com.vpbank.dcp.auth.infrastructure.adapter.out.customer.mapper.CustomerProfileMapper;
import java.util.Objects;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Customer service profile lookup: {@code GET <profilePath>} with the customer ID. 200 is a
 * profile, 404 is "unknown customer", anything else (or a profile for another customer) is
 * unavailable.
 */
@RequiredArgsConstructor
public final class CustomerHttpAdapter implements CustomerDirectoryPort {
    private static final String PARTNER = "Customer service";
    private static final int OK = 200;
    private static final int NOT_FOUND = 404;

    @NonNull private final RestClient restClient;
    /** Has one {@code {customerId}} variable. */
    @NonNull private final String profilePath;
    /** May be null: no bearer header is sent. */
    private final String serviceToken;

    @Override
    public Optional<CustomerProfile> profile(CustomerId customerId) {
        Objects.requireNonNull(customerId, "customerId");
        try {
            return restClient.get()
                    .uri(profilePath, customerId.value())
                    .accept(MediaType.APPLICATION_JSON)
                    .headers(headers -> {
                        if (serviceToken != null) {
                            headers.setBearerAuth(serviceToken);
                        }
                    })
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status == NOT_FOUND) {
                            return Optional.<CustomerProfile>empty();
                        }
                        if (status != OK) {
                            throw new PartnerUnavailableException(PARTNER);
                        }

                        CustomerProfileDto profileDto = response.bodyTo(CustomerProfileDto.class);
                        boolean isRequestedCustomer = profileDto != null
                                && customerId.value().equals(profileDto.customerId());
                        if (!isRequestedCustomer) {
                            throw new PartnerUnavailableException(PARTNER);
                        }

                        CustomerProfile profile = CustomerProfileMapper.toProfile(customerId, profileDto);
                        return Optional.of(profile);
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
