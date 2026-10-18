package com.vpbank.dcp.core.port.out.mfa;

/** Whether the MFA service could open a transaction for this customer and device. */
public sealed interface MfaStartResult {

    record Started(MfaTransaction transaction) implements MfaStartResult { }

    /** The customer has no factor the MFA service can use. Recovery is out of band. */
    record NoUsableFactor() implements MfaStartResult { }
}
