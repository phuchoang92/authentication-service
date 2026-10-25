package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;

import com.vpbank.dcp.auth.domain.model.CustomerId;

import java.util.Optional;

/** The Customer service. Throws {@link PartnerUnavailableException} when it cannot answer. */
public interface CustomerDirectoryPort {

    /** Empty when the Customer service does not know the customer. */
    Optional<CustomerProfile> profile(CustomerId customerId);
}
