package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

public record ExtendSessionResponse(Instant idleExpiresAt, Instant absoluteExpiresAt) { }
