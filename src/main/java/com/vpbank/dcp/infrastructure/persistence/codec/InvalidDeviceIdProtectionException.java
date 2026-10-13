package com.vpbank.dcp.infrastructure.persistence.codec;

public final class InvalidDeviceIdProtectionException extends RuntimeException {
    private static final String MESSAGE = "Device identifier protection is unavailable";

    public InvalidDeviceIdProtectionException() {
        super(MESSAGE);
    }

    public InvalidDeviceIdProtectionException(Throwable cause) {
        super(MESSAGE, cause);
    }
}
