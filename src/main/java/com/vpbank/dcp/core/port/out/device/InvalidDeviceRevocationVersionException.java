package com.vpbank.dcp.core.port.out.device;

public final class InvalidDeviceRevocationVersionException extends IllegalArgumentException {
    public InvalidDeviceRevocationVersionException() {
        super("Device version is outside the supported range");
    }
}
