package com.vpbank.dcp.core.port.in.session;

import java.time.Instant;
import java.util.UUID;

/** Issue only after method-specific factors and current security state are confirmed. */
public interface IssueLoginSessionUseCase {
    SessionLoginResult issue(UUID operationId, Instant now, SessionLoginEvidence evidence);
}
