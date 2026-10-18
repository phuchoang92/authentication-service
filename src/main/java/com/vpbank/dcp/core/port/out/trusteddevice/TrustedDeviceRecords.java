package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import java.util.Optional;

/**
 * Trusted-device rows. Both methods throw {@link TrustedDeviceRecordsUnavailableException} when
 * the database cannot answer; after a failed {@code activate} nothing is assumed committed.
 */
public interface TrustedDeviceRecords {

    /** The key stored for this customer's binding, whatever its status: init keeps it. */
    Optional<StoredDeviceKey> storedKey(SubjectId owner, String channel, BindingId bindingId);

    /**
     * Commits a trust atomically: device row, primary switch, revocation of the previous
     * primary's biometric login, device limit and audit.
     */
    TrustActivationResult activate(TrustActivation activation);
}
