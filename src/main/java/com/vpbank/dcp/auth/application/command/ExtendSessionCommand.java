package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * The BFF names the session by channel and session ID, never by the token's secret. {@code admittedAt}
 * is when the BFF admitted the request; {@code routeId} and {@code admissionId} are correlation.
 */
@Builder
public record ExtendSessionCommand(Channel channel, SessionId sessionId, Instant admittedAt, String routeId,
                                   String admissionId) {
    public ExtendSessionCommand {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(admittedAt, "admittedAt");
        Objects.requireNonNull(routeId, "routeId");
    }
}
