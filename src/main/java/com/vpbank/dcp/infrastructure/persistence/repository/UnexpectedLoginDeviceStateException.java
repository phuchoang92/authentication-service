package com.vpbank.dcp.infrastructure.persistence.repository;

public final class UnexpectedLoginDeviceStateException extends RuntimeException {
    public UnexpectedLoginDeviceStateException() {
        super("Trusted-device lookup returned an inconsistent row set");
    }
}
