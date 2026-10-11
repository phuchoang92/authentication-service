package com.vpbank.dcp.infrastructure.adapter.out.customer;

/** Strict representation of the assumed Customer authentication response. */
record CustomerResponse(String customerId, String status, Long statusVersion,
                        Long lastAccessBlockVersion, String checkedAt) {

    @Override
    public String toString() {
        return "CustomerResponse[redacted]";
    }
}
