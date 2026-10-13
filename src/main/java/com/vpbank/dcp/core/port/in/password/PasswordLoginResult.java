package com.vpbank.dcp.core.port.in.password;

import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import java.time.Instant;

public sealed interface PasswordLoginResult {
    record Active(PreparedSession session) implements PasswordLoginResult { }
    record TotpRequired(String authenticationId, String challengeId, Instant expiresAt,
                        PreparedPendingToken token) implements PasswordLoginResult { }
    record Rejected() implements PasswordLoginResult { }
    record Conflict() implements PasswordLoginResult { }
    record TemporarilyUnavailable() implements PasswordLoginResult { }
}
