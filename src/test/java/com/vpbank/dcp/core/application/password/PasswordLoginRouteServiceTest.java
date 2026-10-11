package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordLoginRouteServiceTest {

    private final PasswordCredentialCheckService credentials = mock(PasswordCredentialCheckService.class);
    private final PasswordDeviceRouteService devices = mock(PasswordDeviceRouteService.class);
    private final PasswordOperationStore operations = mock(PasswordOperationStore.class);
    private final PasswordLoginRouteService service = new PasswordLoginRouteService(
            credentials, devices, operations);
    private final PasswordAdmissionCommand command = mock(PasswordAdmissionCommand.class);

    @Test
    void newDeviceIsDurablyGatedWithoutSessionIssuance() {
        UUID operationId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        var operation = new com.vpbank.dcp.core.port.out.password.PasswordOperationContext(
                operationId, "neo-mobile", "ANDROID", "installation-1234567890", "alice", null);
        Instant now = Instant.parse("2026-10-11T10:00:00Z");
        when(command.operation()).thenReturn(operation);
        when(command.now()).thenReturn(now);
        when(credentials.check(command)).thenReturn(new PasswordCredentialCheckResult.Verified(
                new VerifiedProviderIdentity("https://kc.test", "sub-1"),
                new CustomerAuthenticationState("CUST-1", CustomerStatus.ELIGIBLE,
                        1, 0, now), subjectId));
        when(devices.route(operationId, subjectId, "neo-mobile", now))
                .thenReturn(TrustedDeviceRoute.NEW_DEVICE);
        when(operations.recordMfaUnavailable(operationId, TrustedDeviceRoute.NEW_DEVICE))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);

        assertThat(service.route(command)).isInstanceOf(PasswordLoginRouteResult.MfaUnavailable.class);
        verify(operations).recordMfaUnavailable(operationId, TrustedDeviceRoute.NEW_DEVICE);
    }

    @Test
    void alreadyFrozenMfaRouteNeverChecksCredentialsAgain() {
        when(credentials.check(command)).thenReturn(new PasswordCredentialCheckResult.MfaUnavailable());

        assertThat(service.route(command)).isInstanceOf(PasswordLoginRouteResult.MfaUnavailable.class);
        verifyNoInteractions(devices, operations);
    }
}
