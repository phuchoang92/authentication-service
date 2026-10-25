package com.vpbank.dcp.core.customer;

/** Atomically links a verified provider identity to one immutable business customer. */
public interface CustomerOwnerRepository {

    CustomerOwnerAcceptance accept(VerifiedProviderIdentity identity,
                                   CustomerAuthenticationState snapshot,
                                   String policyVersion);
}
