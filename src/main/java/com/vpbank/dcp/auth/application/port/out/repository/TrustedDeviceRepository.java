package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.List;
import java.util.Optional;

/**
 * TRUSTED_DEVICE, PRIMARY_TRUSTED_DEVICE and TRUSTED_DEVICE_AUDIT (phase 3). The database only
 * stops races (one live row per installation, one primary per customer + channel); every trust
 * rule is decided by the domain first. Throws {@link RepositoryUnavailableException}.
 */
public interface TrustedDeviceRepository {

    /** The live row of this installation, whatever its status. */
    Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId);

    /** Every live row of the customer on the channel (the device list). */
    List<TrustedDevice> findLive(CustomerId customerId, Channel channel);

    Optional<TrustedDeviceId> findPrimary(CustomerId customerId, Channel channel);

    /**
     * The direct path: the device row, the primary assignment and the audit events (sequence 0..n
     * under {@code correlationId}) in one transaction. {@code AlreadyHasDevice} when another login
     * registered a device for this customer + channel first (unique keys).
     */
    TrustFirstResult trustFirstDevice(TrustedDevice device, String correlationId);

    /**
     * The enrollment flow's commit (DD 20 §4, one transaction): replaced and capped rows become EXPIRED,
     * the new row is inserted, the primary row points at it (FACE_CONFIRMED, enrollment ID, face flag),
     * the enrollment is COMPLETED and the audit events are written with the enrollment ID.
     */
    TrustedDevice trustConfirmed(TrustConfirmation confirmation, String correlationId);

    /** Saves a change only if the stored version is still {@code changed.version()}; returns the stored row. */
    Optional<TrustedDevice> saveIfCurrent(TrustedDevice changed, String correlationId);

    sealed interface TrustFirstResult {
        record Trusted(TrustedDevice device) implements TrustFirstResult { }

        record AlreadyHasDevice() implements TrustFirstResult { }
    }
}
