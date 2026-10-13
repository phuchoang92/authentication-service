package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.in.session.ActivateSessionCommand;
import com.vpbank.dcp.core.port.in.session.ActivateSessionUseCase;
import com.vpbank.dcp.core.port.in.session.SessionActivationResult;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.port.out.session.PreparedSession;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordLoginServiceTest {
    private final CheckPasswordLoginEligibilityService eligibility = mock(CheckPasswordLoginEligibilityService.class);
    private final ActivateSessionUseCase sessions = mock(ActivateSessionUseCase.class);
    private final PasswordLoginCommand command = mock(PasswordLoginCommand.class);
    private final com.vpbank.dcp.core.port.out.password.PasswordOperationContext operation =
            mock(com.vpbank.dcp.core.port.out.password.PasswordOperationContext.class);

    @Test
    void onlyLastTrustedCanReceiveActiveSession() {
        UUID operationId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        PreparedSession candidate = mock(PreparedSession.class);
        when(command.operation()).thenReturn(operation);
        when(operation.operationId()).thenReturn(operationId);
        when(eligibility.checkEligibility(command)).thenReturn(new PasswordLoginEligibilityResult.LastTrusted(subjectId));
        when(sessions.activate(new ActivateSessionCommand(operationId, subjectId)))
                .thenReturn(new SessionActivationResult.Active(candidate));

        var result = new PasswordLoginService(eligibility, sessions,
                new PasswordAvailabilityPolicy(true)).login(command);

        assertThat(result).isInstanceOf(PasswordLoginResult.Active.class);
        verify(sessions).activate(new ActivateSessionCommand(operationId, subjectId));
    }

    @Test
    void mfaRouteCannotActivateWithoutRealMfaCapability() {
        when(eligibility.checkEligibility(command)).thenReturn(new PasswordLoginEligibilityResult.MfaUnavailable());

        var result = new PasswordLoginService(eligibility, sessions,
                new PasswordAvailabilityPolicy(true)).login(command);

        assertThat(result).isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(sessions, never()).activate(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void productionGateClosesBeforeCredentialDispatch() {
        var result = new PasswordLoginService(eligibility, sessions,
                new PasswordAvailabilityPolicy(false)).login(command);

        assertThat(result).isInstanceOf(PasswordLoginResult.TemporarilyUnavailable.class);
        verify(eligibility, never()).checkEligibility(command);
    }
}
