package com.vpbank.dcp.core.port.in.mfa;

import com.vpbank.dcp.core.port.out.session.PreparedSession;

public sealed interface ConfirmLoginResult {

    record Active(PreparedSession session) implements ConfirmLoginResult { }

    /** The MFA service has not accepted this transaction yet. The App may elevate and retry. */
    record MfaNotPassed() implements ConfirmLoginResult { }

    record Rejected() implements ConfirmLoginResult { }

    record Unavailable() implements ConfirmLoginResult { }
}
