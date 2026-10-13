package com.vpbank.dcp.core.domain.device;

public final class InvalidDeviceOwnershipException extends IllegalArgumentException {
    public InvalidDeviceOwnershipException() {
        super("Device owner is invalid");
    }
}
