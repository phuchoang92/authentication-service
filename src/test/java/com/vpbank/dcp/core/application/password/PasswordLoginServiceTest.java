package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordLoginServiceTest {
    private final PasswordLoginRouteService routes = mock(PasswordLoginRouteService.class);
    private final ActivatePasswordSessionService sessions = mock(ActivatePasswordSessionService.class);
    private final PasswordLoginCommand command = mock(PasswordLoginCommand.class);
    private final com.vpbank.dcp.core.port.out.password.PasswordOperationContext operation =
            mock(com.vpbank.dcp.core.port.out.password.PasswordOperationContext.class);

    @Test
    void onlyLastTrustedCanReceiveActiveSession() {
        UUID operationId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        PreparedPasswordSession candidate = mock(PreparedPasswordSession.class);
        when(command.operation()).thenReturn(operation);
        when(operation.operationId()).thenReturn(operationId);
        when(routes.route(command)).thenReturn(new PasswordLoginRouteResult.LastTrusted(subjectId));
        when(sessions.activate(operationId, subjectId))
                .thenReturn(new PasswordSessionActivationResult.Active(candidate));

        var result = new PasswordLoginService(routes, sessions,
                new PasswordAvailabilityPolicy(true)).login(command);

        assertThat(result).isInstanceOf(PasswordLoginResult.Active.class);
        verify(sessions).activate(operationId, subjectId);
    }

    @Test
    void mfaRouteCannotActivateWithoutRealMfaCapability() {
        when(routes.route(command)).thenReturn(new PasswordLoginRouteResult.MfaUnavailable());

        var result = new PasswordLoginService(routes, sessions,
                new PasswordAvailabilityPolicy(true)).login(command);

        assertThat(result).isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(sessions, never()).activate(org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void productionGateClosesBeforeCredentialDispatch() {
        var result = new PasswordLoginService(routes, sessions,
                new PasswordAvailabilityPolicy(false)).login(command);

        assertThat(result).isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(routes, never()).route(command);
    }
}
