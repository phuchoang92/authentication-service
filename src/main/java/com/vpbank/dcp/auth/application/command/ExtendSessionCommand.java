package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import lombok.Builder;
import lombok.NonNull;

/**
 * The BFF names the session by channel and session ID, never by the token's secret. {@code admittedAt}
 * is when the BFF admitted the request; {@code routeId} and {@code admissionId} are correlation.
 */
@Builder
public record ExtendSessionCommand(@NonNull Channel channel,
                                   @NonNull SessionId sessionId,
                                   @NonNull Instant admittedAt,
                                   @NonNull String routeId,
                                   String admissionId) {
}
