package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

public enum ServingState {
    CLOSED("CLOSED"),
    REBUILDING("REBUILDING"),
    READY("READY");

    private final String code;

    ServingState(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }

    public static ServingState fromCode(String code) {
        return switch (code) {
            case "CLOSED" -> CLOSED;
            case "REBUILDING" -> REBUILDING;
            case "READY" -> READY;
            default -> throw new InvalidAuthorityValueException();
        };
    }
}
