package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;

public sealed interface PasswordSessionActivationResult {
    record Active(PreparedPasswordSession session) implements PasswordSessionActivationResult { }
    record Processing() implements PasswordSessionActivationResult { }
    record Rejected() implements PasswordSessionActivationResult { }
}
