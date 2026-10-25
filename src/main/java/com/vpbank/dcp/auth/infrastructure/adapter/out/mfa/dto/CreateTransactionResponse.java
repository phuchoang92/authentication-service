package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.Instant;

/** MFA's reply, in the shared envelope: {@code {success, data:{mfaTransactionId, expiresAt}, error:{code}}}. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CreateTransactionResponse(Boolean success, Data data, Error error) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Data(String mfaTransactionId, Instant expiresAt) { }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Error(String code) { }
}
