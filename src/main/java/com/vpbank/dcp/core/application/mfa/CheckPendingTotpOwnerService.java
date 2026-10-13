package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import java.time.Instant;
import java.util.Objects;

/** Rechecks the current Customer and original trusted binding, never caller-provided owner IDs. */
public final class CheckPendingTotpOwnerService {
    private final CustomerDirectory customers;
    private final LoginDeviceRepository devices;

    public CheckPendingTotpOwnerService(CustomerDirectory customers, LoginDeviceRepository devices) {
        this.customers = Objects.requireNonNull(customers);
        this.devices = Objects.requireNonNull(devices);
    }

    public PendingTotpOwner current(PendingTotpLogin pending, Instant now) {
        Objects.requireNonNull(pending);
        Objects.requireNonNull(now);
        CustomerAuthenticationState customer;
        LoginDeviceSnapshot device;
        try {
            customer = customers.currentStatus(pending.identity().customerExternalId());
            device = devices.currentByBinding(pending.identity().customerId(),
                    pending.identity().channel(), pending.identity().installationId(),
                    pending.identity().bindingId()).orElse(null);
        } catch (CustomerDirectoryUnavailableException | LoginDeviceUnavailableException failure) {
            return new PendingTotpOwner.Unavailable();
        }
        if (customer == null || device == null || customer.status() != CustomerStatus.ELIGIBLE
                || !customer.customerId().equals(pending.identity().customerExternalId())
                || customer.statusVersion() != pending.versions().customerStatusVersion()
                || !device.installationMatches() || !device.active()
                || !device.customerId().equals(pending.identity().customerId())
                || !now.isBefore(device.expiresAt())
                || device.securityVersion() != pending.versions().deviceSecurityVersion()
                || !device.deviceKeyThumbprint().equals(Digest32.fromBase64Url(
                        pending.keys().deviceKeyJkt()))) {
            return new PendingTotpOwner.Rejected();
        }
        return new PendingTotpOwner.Current(customer, device);
    }
}
