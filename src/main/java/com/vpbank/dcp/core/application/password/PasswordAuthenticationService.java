package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.AuthenticateWithPassword;
import java.util.Objects;

/** One public password command, with MFA routes closed until their real provider exists. */
public final class PasswordAuthenticationService implements AuthenticateWithPassword {
    private final PasswordLoginRouteService routes;
    private final PasswordSessionService sessions;
    private final PasswordAvailabilityPolicy availability;

    public PasswordAuthenticationService(PasswordLoginRouteService routes,
                                         PasswordSessionService sessions,
                                         PasswordAvailabilityPolicy availability) {
        this.routes = Objects.requireNonNull(routes);
        this.sessions = Objects.requireNonNull(sessions);
        this.availability = Objects.requireNonNull(availability);
    }

    @Override
    public PasswordAuthenticationResult authenticate(PasswordAdmissionCommand command) {
        Objects.requireNonNull(command);
        if (!availability.integrationActivationEnabled()) {
            return new PasswordAuthenticationResult.TemporarilyUnavailable();
        }
        PasswordLoginRouteResult route = routes.route(command);
        if (route instanceof PasswordLoginRouteResult.LastTrusted trusted) {
            PasswordSessionResult issued = sessions.activate(command.operation().operationId(),
                    trusted.subjectId());
            if (issued instanceof PasswordSessionResult.Active active) {
                return new PasswordAuthenticationResult.Active(active.session());
            }
            return issued instanceof PasswordSessionResult.Rejected
                    ? new PasswordAuthenticationResult.Rejected()
                    : new PasswordAuthenticationResult.Processing();
        }
        if (route instanceof PasswordLoginRouteResult.Rejected) {
            return new PasswordAuthenticationResult.Rejected();
        }
        if (route instanceof PasswordLoginRouteResult.Conflict) {
            return new PasswordAuthenticationResult.Conflict();
        }
        if (route instanceof PasswordLoginRouteResult.Processing) {
            return new PasswordAuthenticationResult.Processing();
        }
        return new PasswordAuthenticationResult.TemporarilyUnavailable();
    }
}
