package com.vpbank.dcp.core.device;

public enum DeviceRevocationReason {
    LOST("LOST"),
    STOLEN("STOLEN"),
    CUSTOMER_REQUEST("CUSTOMER_REQUEST"),
    ADMIN_ACTION("ADMIN_ACTION"),
    SECURITY_COMPROMISE("SECURITY_COMPROMISE");

    private final String code;

    DeviceRevocationReason(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
