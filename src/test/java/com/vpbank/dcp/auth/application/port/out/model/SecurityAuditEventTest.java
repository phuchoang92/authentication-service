package com.vpbank.dcp.auth.application.port.out.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.enums.SecurityEventType;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Two shapes on one row: a login event needs its channel, a service-token event its service and scope. */
class SecurityAuditEventTest {
    private static final Instant NOW = Instant.parse("2026-11-03T10:00:00Z");

    @Test
    void aLoginEventNeedsAChannelAndAServiceTokenEventAServiceAndScope() {
        SecurityAuditEvent login = SecurityAuditEvent.builder().reason(SecurityEventReason.UNKNOWN_USER)
                .channel(Channel.WEB).occurredAt(NOW).build();
        assertThat(login.eventType()).isEqualTo(SecurityEventType.LOGIN_FAILED);

        SecurityAuditEvent token = SecurityAuditEvent.builder().reason(SecurityEventReason.TOKEN_ISSUED)
                .serviceId(new ServiceId("onboarding-service")).scope(ServiceScope.ONBOARDING).occurredAt(NOW).build();
        assertThat(token.eventType()).isEqualTo(SecurityEventType.SERVICE_TOKEN_ISSUED);
        assertThat(token.channel()).isNull();

        assertThatThrownBy(() -> SecurityAuditEvent.builder().reason(SecurityEventReason.UNKNOWN_USER).occurredAt(NOW).build())
                .isInstanceOf(NullPointerException.class).hasMessage("channel");
        assertThatThrownBy(() -> SecurityAuditEvent.builder().reason(SecurityEventReason.SCOPE_NOT_GRANTED)
                .scope(ServiceScope.ONBOARDING).occurredAt(NOW).build())
                .isInstanceOf(NullPointerException.class).hasMessage("serviceId");
        assertThatThrownBy(() -> SecurityAuditEvent.builder().reason(SecurityEventReason.SCOPE_NOT_GRANTED)
                .serviceId(new ServiceId("onboarding-service")).occurredAt(NOW).build())
                .isInstanceOf(NullPointerException.class).hasMessage("scope");
    }
}
