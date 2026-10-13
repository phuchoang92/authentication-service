package com.vpbank.dcp.infrastructure.persistence.repository;

public final class UnexpectedDeviceTotpStateException extends IllegalStateException {
    public UnexpectedDeviceTotpStateException() {
        super("Device TOTP credential state is inconsistent");
    }
}
