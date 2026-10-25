package com.vpbank.dcp.auth.adapter.in.web.dto.response;

import java.time.Instant;

public record ExtendSessionResponse(Instant idleExpiresAt, Instant absoluteExpiresAt) { }
