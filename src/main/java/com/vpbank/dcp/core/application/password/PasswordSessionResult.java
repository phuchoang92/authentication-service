package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;

public sealed interface PasswordSessionResult {
    record Active(PreparedPasswordSession session) implements PasswordSessionResult { }
    record Processing() implements PasswordSessionResult { }
    record Rejected() implements PasswordSessionResult { }
}
