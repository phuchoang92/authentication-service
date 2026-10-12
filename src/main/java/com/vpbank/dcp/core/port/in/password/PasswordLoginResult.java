package com.vpbank.dcp.core.port.in.password;

import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;

public sealed interface PasswordLoginResult {
    record Active(PreparedPasswordSession session) implements PasswordLoginResult { }
    record Processing() implements PasswordLoginResult { }
    record Rejected() implements PasswordLoginResult { }
    record Conflict() implements PasswordLoginResult { }
    record TemporarilyUnavailable() implements PasswordLoginResult { }
}
