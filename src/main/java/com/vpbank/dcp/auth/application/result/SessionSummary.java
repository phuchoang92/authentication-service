package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Instant;

/** What a session-checked request may know about its caller; no token, no versions. */
public record SessionSummary(SessionId sessionId, CustomerId customerId, DeviceId deviceId, Channel channel,
                             SessionStatus status, Instant idleExpiresAt, Instant absoluteExpiresAt) { }
