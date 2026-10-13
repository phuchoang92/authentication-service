package com.vpbank.dcp.core.port.out.session;

import java.util.Optional;
import java.util.UUID;

/**
 * Redis is the only online authority; absence or uncertainty never means allow.
 */
public interface SessionAuthority {
    Optional<UUID> currentGeneration();

    SessionApplyResult apply(PreparedSession session);

    boolean deliverable(PreparedSession session);

    /** Remove this exact candidate when post-publication revalidation rejects it. */
    boolean revoke(PreparedSession session);
}
