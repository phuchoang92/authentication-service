package com.vpbank.dcp.auth.application.port.out.repository;

import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * TRUSTED_DEVICE, PRIMARY_TRUSTED_DEVICE and TRUSTED_DEVICE_AUDIT (phase 3). The database only
 * stops races (one live row per installation, one primary per customer + channel); every trust
 * rule is decided by the domain first. Throws {@link RepositoryUnavailableException}.
 */
public interface TrustedDeviceRepository {

    /** The current binding of this installation. The trust deadline is checked by the caller. */
    Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId);

    /** Every current binding of the customer on the channel. */
    List<TrustedDevice> findLive(CustomerId customerId, Channel channel);

    Optional<TrustedDeviceId> findPrimary(CustomerId customerId, Channel channel);

    /** The live row of this installation if it is primary. The caller still checks trust and expiry. */
    Optional<TrustedDevice> findLivePrimary(DeviceInstallation installation);

    /** Updates only login metadata; false when the version or eligible state has changed, or the time is not newer. */
    boolean recordLoginIfCurrent(TrustedDeviceId trustedDeviceId, long expectedVersion, Instant loggedInAt);

    /**
     * Validates the enrollment against its pinned binding and retires any replaced or capped bindings.
     * Saves trust, the primary pointer, the completed enrollment and its audit events in one transaction.
     *
     * <p>Empty, with nothing written, when another commit got there first: the primary enrollment's row
     * already exists (it is inserted only here), the approval's row is no longer at the version the claim
     * read, or a racing commit changed the same rows. Of two commits of one enrollment exactly one returns the
     * trusted device.
     */
    Optional<TrustedDevice> trustConfirmed(TrustConfirmation confirmation, String correlationId);

}
