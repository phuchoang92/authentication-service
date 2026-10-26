package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.util.Objects;

/**
 * How a session is addressed without its secret: the channel and the session ID, both carried in
 * clear by the token (slice 7). The BFF names a session the same way when it asks for an extend.
 */
public record SessionLookup(Channel channel, SessionId sessionId) {
    public SessionLookup {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(sessionId, "sessionId");
    }

    @Override
    public String toString() {
        return channel + ":" + sessionId.value();
    }
}
