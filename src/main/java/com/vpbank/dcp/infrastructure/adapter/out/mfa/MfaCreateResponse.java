package com.vpbank.dcp.infrastructure.adapter.out.mfa;

record MfaCreateResponse(String mfaTransactionId, String expiresAt) {
    @Override
    public String toString() {
        return "MfaCreateResponse[redacted]";
    }
}
