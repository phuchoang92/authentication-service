package com.vpbank.dcp.core.port.in.password;

import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import java.time.Instant;

public sealed interface PasswordLoginResult {

    record Active(PreparedSession session) implements PasswordLoginResult { }

    /** The App must elevate {@code mfaTransactionId} at the MFA service, then confirm here. */
    record MfaRequired(String authenticationId, String mfaTransactionId, Instant expiresAt,
                       PreparedPendingToken token) implements PasswordLoginResult { }

    record Rejected() implements PasswordLoginResult { }

    record Conflict() implements PasswordLoginResult { }

    record TemporarilyUnavailable() implements PasswordLoginResult { }
}
