package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginUseCase;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;

import java.util.Objects;
import java.util.UUID;

/**
 * One public password command, with MFA routes closed until their real provider exists.
 */
public final class PasswordLoginService implements PasswordLoginUseCase {
    private final PasswordLoginRouteService routes;
    private final ActivatePasswordSessionService sessions;
    private final PasswordAvailabilityPolicy availability;

    public PasswordLoginService(PasswordLoginRouteService routes,
                                ActivatePasswordSessionService sessions,
                                PasswordAvailabilityPolicy availability) {
        this.routes = Objects.requireNonNull(routes);
        this.sessions = Objects.requireNonNull(sessions);
        this.availability = Objects.requireNonNull(availability);
    }

    @Override
    public PasswordLoginResult login(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        if (!availability.integrationActivationEnabled()) {
            return new PasswordLoginResult.TemporarilyUnavailable();
        }
        PasswordLoginRouteResult route = routes.route(command);
        switch (route) {
            case PasswordLoginRouteResult.LastTrusted(UUID subjectId) -> {
                PasswordSessionActivationResult issued = sessions.activate(command.operation().operationId(), subjectId);
                if (issued instanceof PasswordSessionActivationResult.Active(PreparedPasswordSession session)) {
                    return new PasswordLoginResult.Active(session);
                }
                return issued instanceof PasswordSessionActivationResult.Rejected
                        ? new PasswordLoginResult.Rejected()
                        : new PasswordLoginResult.Processing();
            }
            case PasswordLoginRouteResult.Rejected _ -> {
                return new PasswordLoginResult.Rejected();
            }
            case PasswordLoginRouteResult.Conflict _ -> {
                return new PasswordLoginResult.Conflict();
            }
            case PasswordLoginRouteResult.Processing _ -> {
                return new PasswordLoginResult.Processing();
            }
            default -> {
            }
        }
        return new PasswordLoginResult.TemporarilyUnavailable();
    }
}
