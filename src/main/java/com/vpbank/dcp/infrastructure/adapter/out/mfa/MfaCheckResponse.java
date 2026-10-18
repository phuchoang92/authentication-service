package com.vpbank.dcp.infrastructure.adapter.out.mfa;

record MfaCheckResponse(String receipt) {
    @Override
    public String toString() {
        return "MfaCheckResponse[redacted]";
    }
}
