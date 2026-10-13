package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import java.util.Objects;

/** Converts a verified password and device route into an actual, bounded login outcome. */
public final class PasswordLoginService implements PasswordLoginUseCase {
    private final AssessPasswordLoginService assessment;
    private final IssueLoginSessionUseCase sessions;
    private final StartTotpLoginService totp;
    private final PasswordAvailabilityPolicy availability;

    public PasswordLoginService(AssessPasswordLoginService assessment,
                                IssueLoginSessionUseCase sessions,
                                StartTotpLoginService totp,
                                PasswordAvailabilityPolicy availability) {
        this.assessment = Objects.requireNonNull(assessment);
        this.sessions = Objects.requireNonNull(sessions);
        this.totp = Objects.requireNonNull(totp);
        this.availability = Objects.requireNonNull(availability);
    }

    @Override
    public PasswordLoginResult login(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        if (!availability.integrationActivationEnabled()) {
            return new PasswordLoginResult.TemporarilyUnavailable();
        }
        PasswordLoginAssessment verified = assessment.assess(command);
        if (verified instanceof PasswordLoginAssessment.LastTrusted primary) {
            var proofs = primary.proofs();
            var keys = new SessionKeyBindings(proofs.requestKey().digest(),
                    proofs.requestPublicJwk(), proofs.responsePublicJwk(),
                    proofs.deviceKeyThumbprint());
            var evidence = new SessionLoginEvidence(primary.customerId(), primary.customer(),
                    primary.device(), keys, primary.generation(), LoginConfirmation.PRIMARY_PASSWORD);
            SessionLoginResult issued = sessions.issue(command.operation().operationId(), command.now(), evidence);
            if (issued instanceof SessionLoginResult.Active active) {
                return new PasswordLoginResult.Active(active.session());
            }
            return issued instanceof SessionLoginResult.Rejected
                    ? new PasswordLoginResult.Rejected()
                    : new PasswordLoginResult.TemporarilyUnavailable();
        }
        if (verified instanceof PasswordLoginAssessment.OtherTrusted other) {
            StartTotpLoginResult started = totp.start(command, other);
            if (started instanceof StartTotpLoginResult.Ready ready) {
                return new PasswordLoginResult.TotpRequired(ready.authenticationId(),
                        ready.challengeId(), ready.expiresAt(), ready.token());
            }
            return started instanceof StartTotpLoginResult.NeedsRecovery
                    ? new PasswordLoginResult.Rejected()
                    : new PasswordLoginResult.TemporarilyUnavailable();
        }
        if (verified instanceof PasswordLoginAssessment.Rejected) {
            return new PasswordLoginResult.Rejected();
        }
        // NEW_DEVICE is deliberately unavailable until provider MFA and reset ACK are wired.
        return new PasswordLoginResult.TemporarilyUnavailable();
    }
}
