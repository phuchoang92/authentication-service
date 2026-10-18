package com.vpbank.dcp.core.port.out.pending;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Optional;

/** Short-lived online authority for a restricted TOTP login. */
public interface PendingMfaLoginStore {
    boolean create(SessionTokenLookup token, PendingMfaLogin pending);

    Optional<PendingMfaLogin> find(SessionTokenLookup token);

    Optional<PendingMfaLogin> consume(SessionTokenLookup token);
}
