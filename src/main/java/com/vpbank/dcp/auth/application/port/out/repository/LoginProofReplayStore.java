package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import java.time.Instant;

/**
 * Proof IDs already used by a login (slice 13): of two logins carrying the same ID exactly one is first.
 * The ID is remembered until the proof could no longer pass the verifier's time check.
 */
public interface LoginProofReplayStore {

    /** @throws RepositoryUnavailableException when the store cannot record the use; the login is then refused */
    boolean firstUse(String proofId, Instant rememberUntil);
}
