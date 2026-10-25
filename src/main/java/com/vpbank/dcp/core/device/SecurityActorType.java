package com.vpbank.dcp.core.device;

public enum SecurityActorType {
    CUSTOMER("CUSTOMER"),
    ADMIN("ADMIN"),
    SYSTEM("SYSTEM");

    private final String code;

    SecurityActorType(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
