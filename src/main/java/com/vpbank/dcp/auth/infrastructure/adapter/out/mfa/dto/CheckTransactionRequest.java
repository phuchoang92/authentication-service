package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto;

/** {@code POST {mfa}/internal/v1/transactions/{id}/check} body (DD 20 §5.4). */
public record CheckTransactionRequest(String authOperationId, String contextDigest) { }
