package com.vpbank.dcp.core.port.out.totp;

import java.util.Objects;

public final class DeviceTotpUnavailableException extends RuntimeException {
    public DeviceTotpUnavailableException(Throwable cause) {
        super("Device TOTP verification is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
