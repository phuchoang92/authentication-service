package com.vpbank.dcp.core.port.out.device;

import java.util.Objects;

public final class LoginDeviceUnavailableException extends RuntimeException {
    public LoginDeviceUnavailableException(Throwable cause) {
        super("Trusted-device storage is unavailable", Objects.requireNonNull(cause, "cause"));
    }
}
