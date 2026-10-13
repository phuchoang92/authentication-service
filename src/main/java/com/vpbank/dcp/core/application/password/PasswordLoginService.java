package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.in.session.ActivateSessionCommand;
import com.vpbank.dcp.core.port.in.session.ActivateSessionUseCase;
import com.vpbank.dcp.core.port.in.session.SessionActivationResult;
import com.vpbank.dcp.core.port.out.session.PreparedSession;

import java.util.Objects;
import java.util.UUID;

/**
 * One public password command, with MFA routes closed until their real provider exists.
 */
public final class PasswordLoginService implements PasswordLoginUseCase {
    private final CheckPasswordLoginEligibilityService eligibility;
    private final ActivateSessionUseCase sessions;
    private final PasswordAvailabilityPolicy availability;

    public PasswordLoginService(CheckPasswordLoginEligibilityService eligibility,
                                ActivateSessionUseCase sessions,
                                PasswordAvailabilityPolicy availability) {
        this.eligibility = Objects.requireNonNull(eligibility);
        this.sessions = Objects.requireNonNull(sessions);
        this.availability = Objects.requireNonNull(availability);
    }

    @Override
    public PasswordLoginResult login(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        if (!availability.integrationActivationEnabled()) {
            return new PasswordLoginResult.TemporarilyUnavailable();
        }
        PasswordLoginEligibilityResult decision = eligibility.checkEligibility(command);
        switch (decision) {
            case PasswordLoginEligibilityResult.LastTrusted(UUID subjectId) -> {
                SessionActivationResult issued = sessions.activate(
                        new ActivateSessionCommand(command.operation().operationId(), subjectId));
                if (issued instanceof SessionActivationResult.Active(PreparedSession session)) {
                    return new PasswordLoginResult.Active(session);
                }
                return issued instanceof SessionActivationResult.Rejected
                        ? new PasswordLoginResult.Rejected()
                        : new PasswordLoginResult.Processing();
            }
            case PasswordLoginEligibilityResult.Rejected _ -> {
                return new PasswordLoginResult.Rejected();
            }
            case PasswordLoginEligibilityResult.Conflict _ -> {
                return new PasswordLoginResult.Conflict();
            }
            case PasswordLoginEligibilityResult.Processing _ -> {
                return new PasswordLoginResult.Processing();
            }
            default -> {
            }
        }
        return new PasswordLoginResult.TemporarilyUnavailable();
    }
}
