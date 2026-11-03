package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import java.time.Instant;

/**
 * One use per BFF assertion (DD 20 §6a): remembers the assertion ID until the assertion would expire anyway.
 * Config backs it with Valkey; the filter never sees the store.
 */
@FunctionalInterface
public interface AssertionReplayGuard {

    /**
     * True the first time this ID is seen, false for every later attempt.
     *
     * @throws RepositoryUnavailableException when the store cannot record the use; the request is not admitted
     */
    boolean firstUse(String assertionId, Instant rememberUntil);
}
