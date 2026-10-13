package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import java.util.Objects;

public sealed interface PasswordDeviceRouteResult {
    record LastTrusted(LoginDeviceSnapshot device) implements PasswordDeviceRouteResult {
        public LastTrusted { Objects.requireNonNull(device); }
    }

    record OtherTrusted(LoginDeviceSnapshot device) implements PasswordDeviceRouteResult {
        public OtherTrusted { Objects.requireNonNull(device); }
    }

    record NewDevice() implements PasswordDeviceRouteResult { }

    record Rejected() implements PasswordDeviceRouteResult { }

    record Unavailable() implements PasswordDeviceRouteResult { }
}
