package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto;

import java.time.Instant;
import java.util.List;
import lombok.Builder;

/** {@code POST {mfa}/internal/v1/transactions} body (DD 20 §5.2). */
@Builder
public record CreateTransactionRequest(String purpose, String customerNumber, String channel, String authOperationId,
                                       List<String> factors, Instant notAfter, String contextDigest) { }
