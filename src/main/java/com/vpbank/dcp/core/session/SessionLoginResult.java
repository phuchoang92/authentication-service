package com.vpbank.dcp.core.session;


public sealed interface SessionLoginResult {
    record Active(PreparedSession session) implements SessionLoginResult { }

    record Rejected() implements SessionLoginResult { }

    record Unavailable() implements SessionLoginResult { }
}
