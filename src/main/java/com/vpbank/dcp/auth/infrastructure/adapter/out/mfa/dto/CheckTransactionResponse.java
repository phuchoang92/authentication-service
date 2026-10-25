package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** MFA's reply: the signed receipt (compact JWS) inside the shared envelope. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CheckTransactionResponse(Boolean success, Data data) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Data(String receipt) { }
}
