package com.vpbank.dcp.auth.core.customer;

import java.util.Optional;

/** The Customer service. Throws {@link PartnerUnavailableException} when it cannot answer. */
public interface CustomerDirectory {

    /** Empty when the Customer service does not know the customer. */
    Optional<CustomerProfile> profile(String customerId);
}
