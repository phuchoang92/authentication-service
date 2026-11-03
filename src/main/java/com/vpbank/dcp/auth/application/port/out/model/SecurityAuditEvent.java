package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.enums.SecurityEventType;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import lombok.Builder;

/**
 * One row of the security activity audit. Carries identifiers only: no user name, password,
 * raw device ID or token (ARCHITECTURE §14). The event type is not a field: it follows from the
 * reason, so no caller can state a contradictory pair, and building an event from values a service
 * always has cannot fail.
 *
 * <p>Two shapes share the row. A login event names the {@code channel} (and customer, platform, session,
 * failed count as known). A service-token event (slice 12) names the {@code serviceId} and {@code scope}
 * instead, plus the {@code tokenId} when one was issued; it has no channel.
 *
 * @param customerId  null when the user name matched no identity, and for service-token events
 * @param channel     null for service-token events
 * @param platform    null on the WEB channel and for service-token events
 * @param sessionId   the session a success issued; null otherwise
 * @param failedCount the lockout count after a counted failure; null otherwise
 * @param serviceId   the calling service of a service-token event; null for login events
 * @param scope       the scope asked for in a service-token event; null for login events
 * @param tokenId     the {@code jti} of an issued service token; null otherwise
 * @param occurredAt  when the service decided
 */
@Builder
public record SecurityAuditEvent(SecurityEventReason reason, CustomerId customerId, Channel channel,
                                 DevicePlatform platform, SessionId sessionId, Integer failedCount,
                                 ServiceId serviceId, ServiceScope scope, UUID tokenId,
                                 Instant occurredAt) {
    public SecurityAuditEvent {
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(occurredAt, "occurredAt");
        if (reason.type().aboutAService()) {
            Objects.requireNonNull(serviceId, "serviceId");
            Objects.requireNonNull(scope, "scope");
        } else {
            Objects.requireNonNull(channel, "channel");
        }
    }

    public SecurityEventType eventType() {
        return reason.type();
    }
}
