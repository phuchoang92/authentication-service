package com.vpbank.dcp.core.port.out.trusteddevice;

/**
 * Commits a trust atomically: device row, primary switch, revocation of the previous primary's
 * biometric login, device limit and audit. Throws {@link TrustedDeviceActivationUnavailableException}
 * when the database cannot answer; nothing is then assumed committed.
 */
public interface TrustedDeviceActivation {
    TrustActivationResult activate(TrustActivation activation);
}
