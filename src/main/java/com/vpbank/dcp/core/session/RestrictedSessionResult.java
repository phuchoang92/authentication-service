package com.vpbank.dcp.core.session;


public sealed interface RestrictedSessionResult {

    record Opened(PreparedRestrictedSession session) implements RestrictedSessionResult { }

    record Unavailable() implements RestrictedSessionResult { }
}
