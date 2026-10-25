package com.vpbank.dcp.auth.domain.exception;

/** A device step was applied to a row that cannot take it: a programming error, not a business outcome. */
public final class DeviceStateException extends IllegalStateException {
    public DeviceStateException(String message) {
        super(message);
    }
}
