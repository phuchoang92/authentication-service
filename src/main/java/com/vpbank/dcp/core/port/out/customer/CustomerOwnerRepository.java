package com.vpbank.dcp.core.port.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
/** Atomically links a verified provider identity to one immutable business customer. */
public interface CustomerOwnerRepository {

    CustomerOwnerAcceptance accept(VerifiedProviderIdentity identity,
                                   CustomerAuthenticationState snapshot,
                                   String policyVersion);
}
