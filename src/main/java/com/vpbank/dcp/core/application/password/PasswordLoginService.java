package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;

import java.util.Objects;

/**
 * The one place the password login branches, and the one place a denial becomes a contract type.
 *
 * <p>The step order is a security constraint, not a style choice: replay markers must be reserved
 * before the password can leave this service, so proof admission runs first.
 */
public final class PasswordLoginService implements PasswordLoginUseCase {
    private final PasswordProofs proofs;
    private final CustomerIdentities identities;
    private final LoginDevices devices;
    private final IssueLoginSessionUseCase sessions;
    private final PasswordAvailabilityPolicy availability;

    public PasswordLoginService(PasswordProofs proofs, CustomerIdentities identities,
                                LoginDevices devices, IssueLoginSessionUseCase sessions,
                                PasswordAvailabilityPolicy availability) {
        this.proofs = Objects.requireNonNull(proofs);
        this.identities = Objects.requireNonNull(identities);
        this.devices = Objects.requireNonNull(devices);
        this.sessions = Objects.requireNonNull(sessions);
        this.availability = Objects.requireNonNull(availability);
    }

    @Override
    public PasswordLoginResult login(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        if (!availability.integrationActivationEnabled()) {
            return denied(LoginDenial.UNAVAILABLE);
        }
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
            // Flow 01: until the trusted-device continuation has an approved contract, both a
            // non-primary trusted device and a new device fail closed with START_NEW_LOGIN.
            // No challenge, pending token or banking token is issued.
            case DeviceTrustResult.OtherTrusted(var _), DeviceTrustResult.NewDevice() ->
                    denied(LoginDenial.UNAVAILABLE);
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
