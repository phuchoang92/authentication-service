package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** Request and status body: where the approval stands and until when it waits. */
public record RequestApprovalResponse(String status, String enrollmentId, Instant expiresAt) { }
