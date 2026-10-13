package com.vpbank.dcp.core.port.out.totp;

/** Checks the current credential and consumes a matching time step exactly once. */
public interface DeviceTotpVerifier {
    DeviceTotpCheckResult verify(CheckDeviceTotp command);
}
