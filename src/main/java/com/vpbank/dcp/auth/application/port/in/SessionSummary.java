package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.SessionId;

import java.time.Instant;

/** What a session-checked request may know about its caller; no token, no versions. */
public record SessionSummary(SessionId sessionId, CustomerId customerId, DeviceId deviceId, Channel channel,
                             Instant idleExpiresAt, Instant absoluteExpiresAt) { }
