package com.vpbank.dcp.infrastructure.persistence.repository;

public final class UnexpectedDeviceRevocationStateException extends RuntimeException {
    public UnexpectedDeviceRevocationStateException() {
        super("Trusted device revocation state is inconsistent");
    }
}
