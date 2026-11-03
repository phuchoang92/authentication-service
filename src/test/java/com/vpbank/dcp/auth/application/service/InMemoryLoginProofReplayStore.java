package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.repository.LoginProofReplayStore;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** Test double with the store's contract: the first caller with an ID wins; later ones are replays. */
final class InMemoryLoginProofReplayStore implements LoginProofReplayStore {
    final Map<String, Instant> used = new HashMap<>();
    boolean unavailable;

    @Override
    public boolean firstUse(String proofId, Instant rememberUntil) {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
        return used.putIfAbsent(proofId, rememberUntil) == null;
    }
}
