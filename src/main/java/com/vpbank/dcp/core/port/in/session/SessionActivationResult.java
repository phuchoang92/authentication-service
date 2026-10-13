package com.vpbank.dcp.core.port.in.session;

import com.vpbank.dcp.core.port.out.session.PreparedSession;

public sealed interface SessionActivationResult {
    record Active(PreparedSession session) implements SessionActivationResult { }
    record Processing() implements SessionActivationResult { }
    record Rejected() implements SessionActivationResult { }
}
