package com.vpbank.dcp.core.port.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;

public interface CustomerDirectory {

    CustomerResolution resolve(VerifiedProviderIdentity identity);

    CustomerAuthenticationState currentStatus(String customerId);
}
