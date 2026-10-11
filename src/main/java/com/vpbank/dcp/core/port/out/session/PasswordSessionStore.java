package com.vpbank.dcp.core.port.out.session;

import java.util.Optional;
import java.util.UUID;

/** Short MySQL transactions only. A prepared result does not authorize use. */
public interface PasswordSessionStore {
    Optional<PasswordSessionFacts> currentFacts(UUID operationId, UUID subjectId);
    PrepareSessionResult prepare(PreparedPasswordSession candidate);
    Optional<PreparedPasswordSession> prepared(UUID operationId);
    boolean markApplied(UUID operationId, UUID intentId);
}
