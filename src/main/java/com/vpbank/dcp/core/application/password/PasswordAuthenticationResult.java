package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;

public sealed interface PasswordAuthenticationResult {
    record Active(PreparedPasswordSession session) implements PasswordAuthenticationResult { }
    record Processing() implements PasswordAuthenticationResult { }
    record Rejected() implements PasswordAuthenticationResult { }
    record Conflict() implements PasswordAuthenticationResult { }
    record TemporarilyUnavailable() implements PasswordAuthenticationResult { }
}
