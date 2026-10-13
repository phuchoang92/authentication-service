package com.vpbank.dcp.core.port.out.session;

import java.util.Optional;
import java.util.UUID;

/** Short MySQL transactions only. A prepared result does not authorize use. */
public interface SessionRepository {
    Optional<SessionActivationFacts> currentFacts(UUID operationId, UUID subjectId);
    PrepareSessionResult prepare(PreparedSession candidate);
    Optional<PreparedSession> prepared(UUID operationId);
    boolean markApplied(UUID operationId, UUID intentId);
}
