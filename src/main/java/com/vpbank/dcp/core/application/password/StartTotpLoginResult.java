package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import java.time.Instant;

public sealed interface StartTotpLoginResult {
    record Ready(String authenticationId, String challengeId, Instant expiresAt,
                 PreparedPendingToken token) implements StartTotpLoginResult { }

    record NeedsRecovery() implements StartTotpLoginResult { }

    record Unavailable() implements StartTotpLoginResult { }
}
