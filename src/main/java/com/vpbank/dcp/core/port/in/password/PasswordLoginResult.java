package com.vpbank.dcp.core.port.in.password;

import com.vpbank.dcp.core.port.out.session.PreparedSession;

public sealed interface PasswordLoginResult {

    record Active(PreparedSession session) implements PasswordLoginResult { }

    record Rejected() implements PasswordLoginResult { }

    record Conflict() implements PasswordLoginResult { }

    record TemporarilyUnavailable() implements PasswordLoginResult { }
}
