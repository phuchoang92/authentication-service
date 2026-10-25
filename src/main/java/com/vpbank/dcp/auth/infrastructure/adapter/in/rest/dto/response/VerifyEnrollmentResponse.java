package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response;

import java.time.Instant;

/** Verify success body: the FACE transaction the app must complete at MFA before confirm. */
public record VerifyEnrollmentResponse(String status, String mfaTransactionId, Instant expiresAt) { }
