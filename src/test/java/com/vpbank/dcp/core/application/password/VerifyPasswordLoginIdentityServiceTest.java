package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
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
import com.vpbank.dcp.core.port.out.password.ConfirmedPasswordOwner;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class VerifyPasswordLoginIdentityServiceTest {

    private final ReservePasswordLoginService admission = mock(ReservePasswordLoginService.class);
    private final PasswordOperationRepository operations = mock(PasswordOperationRepository.class);
    private final DirectGrantPasswordVerifier keycloak = mock(DirectGrantPasswordVerifier.class);
    private final ConfirmPasswordLoginOwnerService customers = mock(ConfirmPasswordLoginOwnerService.class);
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");
    private final VerifyPasswordLoginIdentityService service =
            new VerifyPasswordLoginIdentityService(admission, operations, keycloak, customers,
                    Clock.fixed(now, ZoneOffset.UTC));
    private final UUID operationId = UUID.randomUUID();
    private final PasswordVerification credential =
            new PasswordVerification("alice", "test-only-password");
    private final PasswordLoginCommand command = command();

    private PasswordLoginCommand command() {
        Instant now = Instant.now();
        PasswordOperationContext operation = new PasswordOperationContext(operationId,
                "neo-mobile", "ANDROID", "installation-test", "alice", null);
        PasswordWireProofs proofs = new PasswordWireProofs(mock(VerifiedDpopProof.class), "request-proof", null, "{}");
        return new PasswordLoginCommand(operation, credential, proofs, now,
                now.plusSeconds(120), now.plusSeconds(300));
    }

    @Test
    void committedDispatchPrecedesTheOnlyKeycloakCall() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Verified(identity));
        when(operations.recordVerifiedIdentity(operationId, identity))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);
        CustomerAuthenticationState customer = new CustomerAuthenticationState("CUST-1",
                CustomerStatus.ELIGIBLE, 1, 0, now);
        UUID subjectId = UUID.randomUUID();
        when(customers.confirmOwner(operationId, "neo-mobile", identity, now))
                .thenReturn(new PasswordLoginOwnerResult.Accepted(subjectId, customer));

        assertThat(service.verifyIdentity(command))
                .isEqualTo(new PasswordLoginIdentityResult.Verified(identity, customer, subjectId));
        org.mockito.InOrder ordering = org.mockito.Mockito.inOrder(admission, operations,
                keycloak, customers);
        ordering.verify(admission).reserve(command);
        ordering.verify(operations).claimDispatch(operationId);
        ordering.verify(keycloak).verify(credential);
        ordering.verify(operations).recordVerifiedIdentity(operationId, identity);
        ordering.verify(customers).confirmOwner(operationId, "neo-mobile", identity, now);
        ordering.verifyNoMoreInteractions();
    }

    @Test
    void duplicateDispatchNeverSendsThePasswordAgain() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.ALREADY_CLAIMED);
        when(operations.progress(operationId)).thenReturn(PasswordOperationProgress.DISPATCHED);
        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void reservedCommandCanClaimItsOnlyDispatchAfterAnInterruptedCaller() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Existing(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Rejected());
        when(operations.recordRejection(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);
        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        verify(operations).claimDispatch(operationId);
        verify(keycloak).verify(credential);
    }

    @Test
    void retryReturnsCommittedRejectionWithoutAnotherKeycloakCall() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Existing(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.ALREADY_CLAIMED);
        when(operations.progress(operationId)).thenReturn(PasswordOperationProgress.REJECTED);

        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void retryOfUncertainOperationDoesNotRedispatchCredential() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Existing(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.ALREADY_CLAIMED);
        when(operations.progress(operationId)).thenReturn(PasswordOperationProgress.UNCERTAIN);

        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void retryAfterDurableKeycloakResultResumesCustomerWithoutPasswordRedispatch() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Existing(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.ALREADY_CLAIMED);
        when(operations.progress(operationId)).thenReturn(PasswordOperationProgress.VERIFIED);
        when(operations.verifiedIdentity(operationId)).thenReturn(java.util.Optional.of(identity));
        when(customers.confirmOwner(operationId, "neo-mobile", identity, now))
                .thenReturn(new PasswordLoginOwnerResult.Unavailable());

        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        verify(keycloak, never()).verify(credential);
        verify(customers).confirmOwner(operationId, "neo-mobile", identity, now);
    }

    @Test
    void retryAfterCustomerCommitRecoversOwnerWithoutPasswordRedispatch() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        CustomerAuthenticationState customer = new CustomerAuthenticationState("CUST-1",
                CustomerStatus.ELIGIBLE, 1, 0, now);
        UUID subjectId = UUID.randomUUID();
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Existing(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.ALREADY_CLAIMED);
        when(operations.progress(operationId)).thenReturn(PasswordOperationProgress.CONFIRMED);
        when(operations.confirmedOwner(operationId)).thenReturn(java.util.Optional.of(
                new ConfirmedPasswordOwner(identity, customer, subjectId)));

        assertThat(service.verifyIdentity(command))
                .isEqualTo(new PasswordLoginIdentityResult.Verified(identity, customer, subjectId));
        verify(keycloak, never()).verify(credential);
        verify(customers, never()).confirmOwner(operationId, "neo-mobile", identity, now);
    }

    @Test
    void cancelledOrExpiredOperationNeverSendsThePassword() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId))
                .thenReturn(PasswordDispatchResult.NOT_CLAIMABLE);
        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.NotClaimable.class);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void definiteInvalidGrantRecordsRejectionBeforeReturningIt() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Rejected());
        when(operations.recordRejection(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);
        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        verify(operations).recordRejection(operationId);
    }

    @Test
    void timeoutRecordsUncertaintyAndNeverReturnsRejectionOrSuccess() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenThrow(new KeycloakVerificationUnavailableException());
        when(operations.recordUncertain(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);
        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        verify(operations).recordUncertain(operationId);
    }

    @Test
    void failedUncertaintyWriteDoesNotBecomeAProcessingReceipt() {
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenThrow(new KeycloakVerificationUnavailableException());
        when(operations.recordUncertain(operationId))
                .thenThrow(new IllegalStateException("test-only storage failure"));
        assertThatThrownBy(() -> service.verifyIdentity(command))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void closedAuthorityPreventsCredentialDispatch() {
        when(admission.reserve(command)).thenReturn(new PasswordLoginReservationResult.AuthorityClosed());
        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.AuthorityClosed.class);
        verify(operations, never()).claimDispatch(operationId);
        verify(keycloak, never()).verify(credential);
    }

    @Test
    void blockedCustomerRecordsGenericRejectionAfterVerifiedKeycloakIdentity() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Verified(identity));
        when(customers.confirmOwner(operationId, "neo-mobile", identity, now))
                .thenReturn(new PasswordLoginOwnerResult.Rejected());
        when(operations.recordRejection(operationId))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);

        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Rejected.class);
        verify(operations).recordRejection(operationId);
    }

    @Test
    void customerUnavailabilityDoesNotPermitAnotherPasswordDispatch() {
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
                "https://auth.bank.test/realms/mobile", "kc-user-1");
        when(admission.reserve(command))
                .thenReturn(new PasswordLoginReservationResult.Reserved(operationId, UUID.randomUUID()));
        when(operations.claimDispatch(operationId)).thenReturn(PasswordDispatchResult.CLAIMED);
        when(keycloak.verify(credential)).thenReturn(new PasswordVerificationOutcome.Verified(identity));
        when(customers.confirmOwner(operationId, "neo-mobile", identity, now))
                .thenReturn(new PasswordLoginOwnerResult.Unavailable());
        when(operations.recordVerifiedIdentity(operationId, identity))
                .thenReturn(PasswordCredentialRecordResult.RECORDED);

        assertThat(service.verifyIdentity(command))
                .isInstanceOf(PasswordLoginIdentityResult.Processing.class);
        verify(operations).recordVerifiedIdentity(operationId, identity);
        verify(operations, never()).recordUncertain(operationId);
    }
}
