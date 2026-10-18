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
    private final StartMfaLoginService mfa;
    private final PasswordAvailabilityPolicy availability;

    public PasswordLoginService(PasswordProofs proofs, CustomerIdentities identities,
                                LoginDevices devices, IssueLoginSessionUseCase sessions,
                                StartMfaLoginService mfa,
                                PasswordAvailabilityPolicy availability) {
        this.proofs = Objects.requireNonNull(proofs);
        this.identities = Objects.requireNonNull(identities);
        this.devices = Objects.requireNonNull(devices);
        this.sessions = Objects.requireNonNull(sessions);
        this.mfa = Objects.requireNonNull(mfa);
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
            // NEW_DEVICE stays closed until provider MFA and the reset acknowledgement are wired.
            case DeviceTrustResult.NewDevice() -> denied(LoginDenial.UNAVAILABLE);
            case DeviceTrustResult.LastTrusted(var device) ->
                    issueSession(command, new AuthenticatedLogin(subject, customer, device, proof));
            case DeviceTrustResult.OtherTrusted(var device) ->
                    startMfa(command, new AuthenticatedLogin(subject, customer, device, proof));
        };
    }

    private PasswordLoginResult issueSession(PasswordLoginCommand command, AuthenticatedLogin login) {
        VerifiedPasswordProofs verified = login.proof().proofs();
        SessionLoginEvidence evidence = new SessionLoginEvidence(login.subject(), login.customer(),
                login.device(),
                new SessionKeyBindings(verified.requestKey().digest(), verified.requestPublicJwk(),
                        verified.responsePublicJwk(), verified.deviceKeyThumbprint()),
                login.proof().generation(), LoginConfirmation.PRIMARY_PASSWORD);
        return switch (sessions.issue(command.operation().operationId(), command.now(), evidence)) {
            case SessionLoginResult.Active(var session) -> new PasswordLoginResult.Active(session);
            case SessionLoginResult.Rejected() -> denied(LoginDenial.REJECTED);
            case SessionLoginResult.Unavailable() -> denied(LoginDenial.UNAVAILABLE);
        };
    }

    private PasswordLoginResult startMfa(PasswordLoginCommand command, AuthenticatedLogin login) {
        return switch (mfa.start(command, login)) {
            case StartMfaLoginResult.Ready(
                    var authenticationId, var transactionId,
                    var expiresAt, var token
            ) -> new PasswordLoginResult.MfaRequired(authenticationId, transactionId,
                    expiresAt, token);
            // No enrolled factor cannot be recovered in the App; it is a rejected login here.
            case StartMfaLoginResult.NoUsableFactor() -> denied(LoginDenial.REJECTED);
            case StartMfaLoginResult.Unavailable() -> denied(LoginDenial.UNAVAILABLE);
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
