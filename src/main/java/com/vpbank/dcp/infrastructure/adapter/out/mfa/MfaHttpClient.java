package com.vpbank.dcp.infrastructure.adapter.out.mfa;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import java.util.Objects;

/** Sends MFA requests; does not interpret a status or a receipt. */
public final class MfaHttpClient {
    private final ExternalHttpClient http;

    public MfaHttpClient(ExternalHttpClient http) {
        this.http = Objects.requireNonNull(http, "http");
    }

    ExternalHttpClient.Response<MfaCreateResponse, MfaErrorResponse> create(MfaCreateRequest request) {
        return http.postJson(MfaHttpEndpoints.CREATE, request);
    }

    ExternalHttpClient.Response<MfaCheckResponse, MfaErrorResponse> check(String mfaTransactionId,
                                                                        MfaCheckRequest request) {
        return http.postJson(MfaHttpEndpoints.CHECK.bindSegment("mfaTransactionId", mfaTransactionId),
                request);
    }
}
