package com.vpbank.dcp.core.port.in.session;

import com.vpbank.dcp.core.port.out.session.PreparedSession;

public sealed interface SessionLoginResult {
    record Active(PreparedSession session) implements SessionLoginResult { }

    record Rejected() implements SessionLoginResult { }

    record Unavailable() implements SessionLoginResult { }
}
