package com.vpbank.dcp.core.port.out.session;

public sealed interface PrepareSessionResult {
    record Prepared(PreparedSession session) implements PrepareSessionResult {
    }

    record Existing(PreparedSession session) implements PrepareSessionResult {
    }

    record Rejected() implements PrepareSessionResult {
    }
}
