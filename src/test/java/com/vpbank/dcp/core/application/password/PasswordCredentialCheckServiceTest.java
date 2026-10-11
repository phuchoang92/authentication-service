package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordCredentialCheckServiceTest {

    private final PasswordAdmissionService admission = mock(PasswordAdmissionService.class);
    private final PasswordOperationStore operations = mock(PasswordOperationStore.class);
    private final DirectGrantPasswordVerifier keycloak = mock(DirectGrantPasswordVerifier.class);
    private final CustomerSnapshotCheckService customers = mock(CustomerSnapshotCheckService.class);
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");
    private final PasswordCredentialCheckService service =
            new PasswordCredentialCheckService(admission, operations, keycloak, customers,
                    Clock.fixed(now, ZoneOffset.UTC));
    private final UUID operationId = UUID.randomUUID();
    private final PasswordVerification credential =
            new PasswordVerification("alice", "test-only-password");
    private final PasswordAdmissionCommand command = command();

    private PasswordAdmissionCommand command() {
        Instant now = Instant.now();
        PasswordOperationContext operation = new PasswordOperationContext(operationId,
                "neo-mobile", "ANDROID", "installation-test", "alice", null);
        PasswordWireProofs proofs = new PasswordWireProofs(
                URI.create("https://api.bank.test/api/v1/authentications/password"),
                "dpop", "request-proof", null, "{}");
        return new PasswordAdmissionCommand(operation, credential, proofs, now,
                now.plusSeconds(120), now.plusSeconds(300));
    }

    @Test
    void committedDispatchPrecedesTheOnlyKeycloakCall() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Verified(identity));
        CustomerAuthenticationState customer = new CustomerAuthenticationState("CUST-1",
                CustomerStatus.ELIGIBLE, 1, 0, now);
        when(customers.check(identity, now))
                .thenReturn(new CustomerSnapshotCheckResult.Eligible(customer));

        assertThat(service.check(command))
                .isEqualTo(new PasswordCredentialCheckResult.Verified(identity, customer));
        org.mockito.InOrder ordering = org.mockito.Mockito.inOrder(admission, operations,
                keycloak, customers);
        ordering.verify(admission).reserve(command);
        ordering.verify(operations).claimDispatch(operationId);
        ordering.verify(keycloak).verify(credential);
        ordering.verify(customers).check(identity, now);
        ordering.verifyNoMoreInteractions();
    }

    @Test
    void duplicateDispatchNeverSendsThePasswordAgain() {
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.ALREADY_CLAIMED);
        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.Processing.class);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void sameSemanticCommandReturnsOriginalOperationWithoutAnotherDispatch() {
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Existing(operationId, UUID.randomUUID()));
        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.Processing.class);
        verify(operations, never()).claimDispatch(operationId);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void cancelledOrExpiredOperationNeverSendsThePassword() {
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.NOT_CLAIMABLE);
        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.NotClaimable.class);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void definiteInvalidGrantRecordsRejectionBeforeReturningIt() {
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Rejected());
        when(operations.recordRejection(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);
        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.Rejected.class);
        verify(operations).recordRejection(operationId);
    }

    @Test
    void timeoutRecordsUncertaintyAndNeverReturnsRejectionOrSuccess() {
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenThrow(new KeycloakVerificationUnavailableException());
        when(operations.recordUncertain(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);
        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.Processing.class);
        verify(operations).recordUncertain(operationId);
    }

    @Test
    void failedUncertaintyWriteDoesNotBecomeAProcessingReceipt() {
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenThrow(new KeycloakVerificationUnavailableException());
        when(operations.recordUncertain(operationId))
                .thenThrow(new IllegalStateException("test-only storage failure"));
        assertThatThrownBy(() -> service.check(command))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void closedAuthorityPreventsCredentialDispatch() {
        when(admission.reserve(command)).thenReturn(new PasswordAdmissionResult.AuthorityClosed());
        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.AuthorityClosed.class);
        verify(operations, never()).claimDispatch(operationId);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void blockedCustomerRecordsGenericRejectionAfterVerifiedKeycloakIdentity() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Verified(identity));
        when(customers.check(identity, now)).thenReturn(new CustomerSnapshotCheckResult.Rejected());
        when(operations.recordRejection(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);

        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.Rejected.class);
        verify(operations).recordRejection(operationId);
    }

    @Test
    void customerUnavailabilityDoesNotPermitAnotherPasswordDispatch() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordAdmissionResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Verified(identity));
        when(customers.check(identity, now)).thenReturn(new CustomerSnapshotCheckResult.Unavailable());
        when(operations.recordUncertain(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);

        assertThat(service.check(command))
                .isInstanceOf(PasswordCredentialCheckResult.Processing.class);
        verify(operations).recordUncertain(operationId);
    }
}
