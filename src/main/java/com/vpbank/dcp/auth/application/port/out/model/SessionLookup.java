package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.SessionId;
import lombok.NonNull;

/**
 * How a session is addressed without its secret: the channel and the session ID, both carried in
 * clear by the token (slice 7). The BFF names a session the same way when it asks for an extend.
 */
public record SessionLookup(@NonNull Channel channel, @NonNull SessionId sessionId) {
    @Override
    public String toString() {
        return channel + ":" + sessionId.value();
    }
}
