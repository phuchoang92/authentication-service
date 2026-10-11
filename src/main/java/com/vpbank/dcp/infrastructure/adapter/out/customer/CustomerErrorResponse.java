package com.vpbank.dcp.infrastructure.adapter.out.customer;

/** Strict assumed Customer error schema; never logged as a response body. */
record CustomerErrorResponse(String code, String correlationId) {

    @Override
    public String toString() {
        return "CustomerErrorResponse[redacted]";
    }
}
