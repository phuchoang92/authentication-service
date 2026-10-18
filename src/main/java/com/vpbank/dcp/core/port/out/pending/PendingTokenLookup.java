package com.vpbank.dcp.core.port.out.pending;

import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;

/** Turns an exact opaque token into a keyed lookup; never stores or logs plaintext. */
public interface PendingTokenLookup {
    SessionTokenLookup forExactToken(String exactToken);
}
