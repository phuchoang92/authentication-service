package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.application.port.out.model.SessionLookup;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;

/**
 * The session key factory (RK02/RK03): {@code session:v1:<channel>:<sessionId>}, both taken in clear
 * from the token (slice 7). No key material, no I/O, no clock, no TTL decisions here (RK10); the BFF
 * builds the same key from the same token.
 */
public final class SessionKeys {
    static final String PREFIX = "session:v1:";

    public SessionLookup lookupOf(OpaqueToken token) {
        return new SessionLookup(token.channel(), token.sessionId());
    }

    public String forLookup(SessionLookup lookup) {
        return PREFIX + lookup.channel().name() + ":" + lookup.sessionId().value();
    }
}
