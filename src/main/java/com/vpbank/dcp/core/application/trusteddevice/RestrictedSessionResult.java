package com.vpbank.dcp.core.application.trusteddevice;

import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;

public sealed interface RestrictedSessionResult {

    record Opened(PreparedRestrictedSession session) implements RestrictedSessionResult { }

    record Unavailable() implements RestrictedSessionResult { }
}
