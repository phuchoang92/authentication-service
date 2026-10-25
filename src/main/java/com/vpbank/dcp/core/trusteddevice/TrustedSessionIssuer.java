package com.vpbank.dcp.core.trusteddevice;

import com.vpbank.dcp.core.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.device.BindingId;
import com.vpbank.dcp.core.session.IssueLoginSessionService;
import com.vpbank.dcp.core.session.LoginConfirmation;
import com.vpbank.dcp.core.session.SessionLoginEvidence;
import com.vpbank.dcp.core.session.SessionLoginResult;
import com.vpbank.dcp.core.customer.CustomerDirectory;
import com.vpbank.dcp.core.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.core.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.session.SessionKeyBindings;
import com.vpbank.dcp.core.session.RestrictedSession;
import java.time.Instant;
import java.util.Objects;

/**
 * Issues the ACTIVE session that ends a trust, through the same guarded issuance as a primary
 * password login. Customer is read again: its status at login may be minutes old by now.
 */
public final class TrustedSessionIssuer {
    private final CustomerDirectory customers;
    private final LoginDeviceRepository devices;
    private final IssueLoginSessionService sessions;

    public TrustedSessionIssuer(CustomerDirectory customers, LoginDeviceRepository devices,
                                IssueLoginSessionService sessions) {
        this.customers = Objects.requireNonNull(customers);
        this.devices = Objects.requireNonNull(devices);
        this.sessions = Objects.requireNonNull(sessions);
    }

    public ConfirmTrustedDeviceResult issue(RestrictedSession login, BindingId binding,
                                            String deviceId, Instant now) {
        CustomerAuthenticationState customer;
        LoginDeviceSnapshot device;
        try {
            customer = customers.currentStatus(login.customer().number());
            device = devices.currentByBinding(login.customer().owner(), login.device().channel(),
                    deviceId, binding).orElse(null);
        } catch (CustomerDirectoryUnavailableException | LoginDeviceUnavailableException failure) {
            return new ConfirmTrustedDeviceResult.Unavailable();
        }
        // A changed Customer status needs a fresh login, which records the new owner snapshot.
        if (!customer.status().allowsLogin()
                || customer.statusVersion() != login.customer().statusVersion()
                || device == null || !device.deviceIdMatches()
                || !device.standing().active() || !device.standing().primary()) {
            return new ConfirmTrustedDeviceResult.Rejected();
        }
        SessionLoginEvidence evidence = new SessionLoginEvidence(login.customer().owner(), customer,
                device, new SessionKeyBindings(login.keys().requestKeyThumbprint(),
                        login.keys().requestPublicJwk(), login.keys().responsePublicJwk(),
                        device.deviceKeyThumbprint()),
                login.generation(), LoginConfirmation.MFA_CONFIRMED);
        return switch (sessions.issue(login.operationId(), now, evidence)) {
            case SessionLoginResult.Active(var session) -> new ConfirmTrustedDeviceResult.Active(session);
            case SessionLoginResult.Rejected() -> new ConfirmTrustedDeviceResult.Rejected();
            case SessionLoginResult.Unavailable() -> new ConfirmTrustedDeviceResult.Unavailable();
        };
    }
}
