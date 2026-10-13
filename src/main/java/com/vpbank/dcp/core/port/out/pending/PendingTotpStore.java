package com.vpbank.dcp.core.port.out.pending;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Optional;

/** Short-lived online authority for a restricted TOTP login. */
public interface PendingTotpStore {
    boolean create(SessionTokenLookup token, PendingTotpLogin pending);

    Optional<PendingTotpLogin> find(SessionTokenLookup token);

    Optional<PendingTotpLogin> consume(SessionTokenLookup token);
}
