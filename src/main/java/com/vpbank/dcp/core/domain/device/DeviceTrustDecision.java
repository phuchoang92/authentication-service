package com.vpbank.dcp.core.domain.device;

public enum DeviceTrustDecision {
    /** The current primary binding, proven by its key: the login can become ACTIVE. */
    LAST_TRUSTED,
    /** A valid binding of this customer that is not the primary one. */
    OTHER_TRUSTED,
    /** This customer's binding, proven by its key, but revoked or expired. */
    TRUST_LAPSED,
    /** No binding was claimed. */
    NEW_DEVICE,
    /** A claimed binding that is not this customer's, or that its key does not prove. */
    REJECTED
}
