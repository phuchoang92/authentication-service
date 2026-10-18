package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import java.time.Instant;

/** The MFA transaction was opened, or this login cannot continue now. */
public sealed interface StartMfaLoginResult {

    record Ready(String authenticationId, String mfaTransactionId, Instant expiresAt,
                 PreparedPendingToken token) implements StartMfaLoginResult { }

    /** The customer has no usable factor: this login cannot be completed in the App. */
    record NoUsableFactor() implements StartMfaLoginResult { }

    record Unavailable() implements StartMfaLoginResult { }
}
