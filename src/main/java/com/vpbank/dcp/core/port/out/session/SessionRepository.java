package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.util.Optional;
import java.util.UUID;

/** Short MySQL transactions only. A prepared result does not authorize use. */
public interface SessionRepository {
    Optional<SessionActivationSnapshot> currentSnapshot(UUID operationId, SubjectId subject);
    PrepareSessionResult prepare(PreparedSession candidate);
    Optional<PreparedSession> prepared(UUID operationId);
    boolean markApplied(UUID operationId, UUID intentId);
}
