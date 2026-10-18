package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;

/** Which login the resolved device is entitled to. */
public sealed interface DeviceTrustResult {

    record LastTrusted(LoginDeviceSnapshot device) implements DeviceTrustResult { }

    record OtherTrusted(LoginDeviceSnapshot device) implements DeviceTrustResult { }

    record NewDevice() implements DeviceTrustResult { }

    record Denied(LoginDenial why) implements DeviceTrustResult { }
}
