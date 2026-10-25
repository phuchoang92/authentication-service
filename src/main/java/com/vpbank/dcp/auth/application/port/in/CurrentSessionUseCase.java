package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.result.SessionSummary;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;

import java.util.Optional;

/** The session-check filter: who is behind this token right now? Read-only, never touches idle time. */
public interface CurrentSessionUseCase {
    Optional<SessionSummary> resolve(OpaqueToken token);
}
