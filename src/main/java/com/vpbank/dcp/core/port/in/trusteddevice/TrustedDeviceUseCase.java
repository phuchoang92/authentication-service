package com.vpbank.dcp.core.port.in.trusteddevice;

import java.time.Instant;

/** init → verify → confirm for a NEED_TRUSTED_DEVICE session (draft doc 20 §4). */
public interface TrustedDeviceUseCase {

    /** {@code devicePublicJwk} is required for a new device and must be absent for a known one. */
    InitTrustedDeviceResult init(TrustedDeviceCaller caller, String devicePublicJwk, Instant now);

    VerifyTrustedDeviceResult verify(TrustedDeviceCaller caller, String challengeResponseJwe,
                                     Instant now);

    ConfirmTrustedDeviceResult confirm(TrustedDeviceCaller caller, Instant now);
}
