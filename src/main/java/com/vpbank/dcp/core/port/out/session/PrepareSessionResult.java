package com.vpbank.dcp.core.port.out.session;

public sealed interface PrepareSessionResult {
    record Prepared(PreparedPasswordSession session) implements PrepareSessionResult { }
    record Existing(PreparedPasswordSession session) implements PrepareSessionResult { }
    record Rejected() implements PrepareSessionResult { }
}
