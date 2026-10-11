package com.vpbank.dcp.core.port.out.customer;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import java.util.UUID;

/** Atomically links verified KC identity and Customer owner to the claimed operation. */
public interface CustomerOwnerStore {

    CustomerOwnerAcceptance accept(UUID operationId, String appId,
                                   VerifiedProviderIdentity identity,
                                   CustomerAuthenticationState snapshot,
                                   String policyVersion);
}
