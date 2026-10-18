package com.vpbank.dcp.core.application.trusteddevice;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.in.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import java.time.Instant;
import java.util.Objects;

/**
 * Issues the ACTIVE session that ends a trust, through the same guarded issuance as a primary
 * password login. Customer is read again: its status at login may be minutes old by now.
 */
public final class TrustedSessionIssuer {
    private final CustomerDirectory customers;
    private final LoginDeviceRepository devices;
    private final IssueLoginSessionUseCase sessions;

    public TrustedSessionIssuer(CustomerDirectory customers, LoginDeviceRepository devices,
                                IssueLoginSessionUseCase sessions) {
        this.customers = Objects.requireNonNull(customers);
        this.devices = Objects.requireNonNull(devices);
        this.sessions = Objects.requireNonNull(sessions);
    }

    public ConfirmTrustedDeviceResult issue(StoredRestrictedSession trust, BindingId binding,
                                            String deviceId, Instant now) {
        CustomerAuthenticationState customer;
        LoginDeviceSnapshot device;
        try {
            customer = customers.currentStatus(trust.customerNumber());
            device = devices.currentByBinding(trust.owner(), trust.channel(), deviceId, binding)
                    .orElse(null);
        } catch (CustomerDirectoryUnavailableException | LoginDeviceUnavailableException failure) {
            return new ConfirmTrustedDeviceResult.Unavailable();
        }
        // A changed Customer status needs a fresh login, which records the new owner snapshot.
        if (!customer.status().allowsLogin()
                || customer.statusVersion() != trust.customerStatusVersion()
                || device == null || !device.deviceIdMatches() || !device.active() || !device.primary()) {
            return new ConfirmTrustedDeviceResult.Rejected();
        }
        SessionLoginEvidence evidence = new SessionLoginEvidence(trust.owner(), customer, device,
                new SessionKeyBindings(trust.keys().requestKeyThumbprint(),
                        trust.keys().requestPublicJwk(), trust.keys().responsePublicJwk(),
                        device.deviceKeyThumbprint()),
                trust.generation(), LoginConfirmation.MFA_CONFIRMED);
        return switch (sessions.issue(trust.operationId(), now, evidence)) {
            case SessionLoginResult.Active(var session) -> new ConfirmTrustedDeviceResult.Active(session);
            case SessionLoginResult.Rejected() -> new ConfirmTrustedDeviceResult.Rejected();
            case SessionLoginResult.Unavailable() -> new ConfirmTrustedDeviceResult.Unavailable();
        };
    }
}
