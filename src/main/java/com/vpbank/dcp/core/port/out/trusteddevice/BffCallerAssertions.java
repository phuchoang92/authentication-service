package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import java.time.Instant;
import java.util.Optional;

/** The Mobile BFF's signed assertion naming the caller of one trusted-device step. */
public interface BffCallerAssertions {
    /**
     * Empty for anything but a valid assertion used for the first time. Throws
     * {@code ReplayAuthorityUnavailableException} when its single use cannot be recorded.
     */
    Optional<TrustedDeviceCaller> accept(String compactAssertion, Instant now);
}
