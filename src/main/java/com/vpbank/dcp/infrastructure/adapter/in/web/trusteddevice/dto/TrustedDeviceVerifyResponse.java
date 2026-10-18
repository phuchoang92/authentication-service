package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import java.util.Objects;

public record TrustedDeviceVerifyResponse(String status, String mfaTransactionId)
        implements TrustedDeviceResponse {
    public TrustedDeviceVerifyResponse {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(mfaTransactionId, "mfaTransactionId");
    }
}
