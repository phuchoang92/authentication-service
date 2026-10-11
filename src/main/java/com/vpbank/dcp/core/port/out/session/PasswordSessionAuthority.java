package com.vpbank.dcp.core.port.out.session;

import java.util.Optional;
import java.util.UUID;

/** Redis is the only online authority; absence or uncertainty never means allow. */
public interface PasswordSessionAuthority {
    Optional<UUID> currentGeneration();
    SessionApplyResult apply(PreparedPasswordSession session);
    boolean deliverable(PreparedPasswordSession session);
}
