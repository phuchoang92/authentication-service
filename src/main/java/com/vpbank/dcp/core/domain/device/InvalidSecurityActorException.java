package com.vpbank.dcp.core.domain.device;

public final class InvalidSecurityActorException extends IllegalArgumentException {
    public InvalidSecurityActorException() {
        super("Security actor is invalid");
    }
}
