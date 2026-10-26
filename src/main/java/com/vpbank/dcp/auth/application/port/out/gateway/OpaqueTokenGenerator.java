package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.SessionId;

/** The token of a new session: its channel and ID in clear plus 32 random bytes. Randomness is a boundary, so it is a port. */
public interface OpaqueTokenGenerator {
    OpaqueToken next(Channel channel, SessionId sessionId);
}
