package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.session.PinnedDevice;
import com.vpbank.dcp.core.session.PinnedCustomer;
import com.vpbank.dcp.core.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.session.IssueLoginSessionService;
import com.vpbank.dcp.core.session.LoginConfirmation;
import com.vpbank.dcp.core.session.SessionLoginEvidence;
import com.vpbank.dcp.core.session.SessionLoginResult;
import com.vpbank.dcp.core.session.RestrictedSessionResult;
import com.vpbank.dcp.core.session.TrustedDeviceSessions;
import com.vpbank.dcp.core.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.session.LoginKeys;
import com.vpbank.dcp.core.session.RestrictedSession;
import com.vpbank.dcp.core.session.TrustTarget;
import com.vpbank.dcp.core.session.SessionKeyBindings;

import java.util.Objects;

/**
 * The one place the password login branches, and the one place a denial becomes a contract type.
 *
 * <p>The step order is a security constraint, not a style choice: replay markers must be reserved
 * before the password can leave this service, so proof admission runs first.
 */
public final class PasswordLoginService {
    private final PasswordProofs proofs;
    private final CustomerIdentities identities;
    private final LoginDevices devices;
    private final IssueLoginSessionService sessions;
    private final TrustedDeviceSessions trustedDevices;

    public PasswordLoginService(PasswordProofs proofs, CustomerIdentities identities,
                                LoginDevices devices, IssueLoginSessionService sessions,
                                TrustedDeviceSessions trustedDevices) {
        this.proofs = Objects.requireNonNull(proofs);
        this.identities = Objects.requireNonNull(identities);
        this.devices = Objects.requireNonNull(devices);
        this.sessions = Objects.requireNonNull(sessions);
        this.trustedDevices = Objects.requireNonNull(trustedDevices);
    }

    public PasswordLoginResult login(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        return switch (proofs.admit(command)) {
            case PasswordProofAdmissionResult.Denied(var why) -> denied(why);
            case PasswordProofAdmissionResult.Admitted(var proof) -> confirmOwner(command, proof);
        };
    }

    /**
     * Replay markers are reserved: from here this password is dispatched exactly once.
     */
    private PasswordLoginResult confirmOwner(PasswordLoginCommand command, AdmittedProof proof) {
        return switch (identities.confirm(command)) {
            case PasswordIdentityResult.Denied(var why) -> denied(why);
            case PasswordIdentityResult.Verified(var subject, var customer) ->
                    routeDevice(command, proof, subject, customer);
        };
    }

    /**
     * The owner is accepted; the device decides whether this login can complete now.
     */
    private PasswordLoginResult routeDevice(PasswordLoginCommand command, AdmittedProof proof,
                                            SubjectId subject, CustomerAuthenticationState customer) {
        return switch (devices.decide(subject, command, proof.proofs())) {
            case DeviceTrustResult.Denied(var why) -> denied(why);
            case DeviceTrustResult.LastTrusted(var device) ->
                    issueSession(command, new SessionLoginEvidence(subject, customer, device,
                            keyBindings(proof.proofs()), proof.generation(),
                            LoginConfirmation.PRIMARY_PASSWORD));
            // Every other device continues through the trusted-device API (draft doc 20): a
            // non-primary binding, a revoked or expired one, and a device with no binding.
            case DeviceTrustResult.OtherTrusted(var device) ->
                    needTrustedDevice(command, proof, subject, customer, known(device));
            case DeviceTrustResult.Lapsed(var device) ->
                    needTrustedDevice(command, proof, subject, customer, known(device));
            case DeviceTrustResult.NewDevice() ->
                    needTrustedDevice(command, proof, subject, customer,
                            new TrustTarget.NewDevice());
        };
    }

    private static SessionKeyBindings keyBindings(VerifiedPasswordProofs verified) {
        return new SessionKeyBindings(verified.requestKey().digest(), verified.requestPublicJwk(),
                verified.responsePublicJwk(), verified.deviceKeyThumbprint());
    }

    private PasswordLoginResult issueSession(PasswordLoginCommand command, SessionLoginEvidence evidence) {
        return switch (sessions.issue(command.operation().operationId(), command.now(), evidence)) {
            case SessionLoginResult.Active(var session) -> new PasswordLoginResult.Active(session);
            case SessionLoginResult.Rejected() -> denied(LoginDenial.REJECTED);
            case SessionLoginResult.Unavailable() -> denied(LoginDenial.UNAVAILABLE);
        };
    }

    private PasswordLoginResult needTrustedDevice(PasswordLoginCommand command, AdmittedProof proof,
                                                  SubjectId subject,
                                                  CustomerAuthenticationState customer,
                                                  TrustTarget target) {
        VerifiedPasswordProofs verified = proof.proofs();
        RestrictedSession session = new RestrictedSession(command.operation().operationId(),
                new PinnedCustomer(subject, customer.customerNumber(), customer.statusVersion()),
                new PinnedDevice(command.operation().appId(), command.operation().platform(), target),
                new LoginKeys(verified.requestPublicJwk(), verified.requestKey().digest(),
                        verified.responsePublicJwk()),
                proof.generation());
        return switch (trustedDevices.open(session, command.operation().deviceId(), command.now())) {
            case RestrictedSessionResult.Opened(var opened) ->
                    new PasswordLoginResult.NeedTrustedDevice(opened.tokenEnvelope(),
                            opened.receipt(), opened.expiresAt());
            case RestrictedSessionResult.Unavailable() -> denied(LoginDenial.UNAVAILABLE);
        };
    }

    private static TrustTarget known(LoginDeviceSnapshot device) {
        return new TrustTarget.KnownDevice(device.bindingId(), device.deviceKeyThumbprint(),
                device.securityVersion());
    }

    /**
     * The single translation from an internal denial to the published BFF contract.
     */
    private static PasswordLoginResult denied(LoginDenial why) {
        return switch (why) {
            case REJECTED -> new PasswordLoginResult.Rejected();
            case UNAVAILABLE -> new PasswordLoginResult.TemporarilyUnavailable();
        };
    }
}
