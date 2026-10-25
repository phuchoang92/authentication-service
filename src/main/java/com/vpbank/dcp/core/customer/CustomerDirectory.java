package com.vpbank.dcp.core.customer;


public interface CustomerDirectory {

    CustomerResolution resolve(VerifiedProviderIdentity identity);

    CustomerAuthenticationState currentStatus(CustomerNumber customerNumber);
}
