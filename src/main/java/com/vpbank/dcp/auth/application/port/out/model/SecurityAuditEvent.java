package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.enums.SecurityEventType;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * One row of the security activity audit. Carries identifiers only: no user name, password,
 * raw device ID or token (ARCHITECTURE §14). The event type is not a field: it follows from the
 * reason, so no caller can state a contradictory pair, and building an event from values a service
 * always has cannot fail.
 *
 * @param customerId  null when the user name matched no identity
 * @param platform    null on the WEB channel
 * @param sessionId   the session a success issued; null otherwise
 * @param failedCount the lockout count after a counted failure; null otherwise
 * @param occurredAt  when the service decided
 */
@Builder
public record SecurityAuditEvent(SecurityEventReason reason, CustomerId customerId, Channel channel,
                                 DevicePlatform platform, SessionId sessionId, Integer failedCount,
                                 Instant occurredAt) {
    public SecurityAuditEvent {
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(occurredAt, "occurredAt");
    }

    public SecurityEventType eventType() {
        return reason.type();
    }
}
