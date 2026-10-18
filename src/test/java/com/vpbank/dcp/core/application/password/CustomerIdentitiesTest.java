package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.customer.CheckCustomerLoginEligibilityUseCase;
import com.vpbank.dcp.core.port.in.customer.CustomerLoginEligibilityResult;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerUnavailableException;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifier;
import com.vpbank.dcp.core.port.out.credential.PasswordVerifierUnavailableException;
import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
import com.vpbank.dcp.core.port.out.credential.PasswordVerificationOutcome;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CustomerIdentitiesTest {
    private final PasswordVerifier passwords = mock(PasswordVerifier.class);
    private final CheckCustomerLoginEligibilityUseCase customers =
            mock(CheckCustomerLoginEligibilityUseCase.class);
    private final CustomerOwnerRepository owners = mock(CustomerOwnerRepository.class);
    private final CustomerIdentities service =
            new CustomerIdentities(passwords, customers, owners, "test-policy");

    private final PasswordLoginCommand command = command();
    private final VerifiedProviderIdentity identity =
            new VerifiedProviderIdentity("https://auth.bank.test/realms/mobile", "kc-a");
    private final CustomerAuthenticationState customer =
            new CustomerAuthenticationState(new CustomerNumber("CUST-1"), CustomerStatus.ELIGIBLE, 1, 0,
                    Instant.parse("2026-10-13T00:00:00Z"));

    @Test
    void eligibleSnapshotAndDurableOwnerAreBothRequired() {
        SubjectId subject = new SubjectId(UUID.randomUUID());
        passwordVerifies();
        when(customers.checkEligibility(identity, command.now()))
                .thenReturn(new CustomerLoginEligibilityResult.Eligible(customer));
        when(owners.accept(identity, customer, "test-policy"))
                .thenReturn(new CustomerOwnerAcceptance.Accepted(subject));

        assertThat(service.confirm(command))
                .isEqualTo(new PasswordIdentityResult.Verified(subject, customer));
        verify(owners).accept(identity, customer, "test-policy");
    }

    @Test
    void rejectedPasswordNeverQueriesCustomer() {
        when(passwords.verify(command.credential()))
                .thenReturn(new PasswordVerificationOutcome.Rejected());

        assertThat(service.confirm(command))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));
        verifyNoInteractions(customers);
        verifyNoInteractions(owners);
    }

    @Test
    void timeoutReturnsUnavailableWithoutRetryOrCustomerLookup() {
        when(passwords.verify(command.credential()))
                .thenThrow(new PasswordVerifierUnavailableException());

        assertThat(service.confirm(command))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE));
        verify(passwords).verify(command.credential());
        verifyNoInteractions(customers);
        verifyNoInteractions(owners);
    }

    @Test
    void unavailableCustomerNeverTouchesOwnerStore() {
        passwordVerifies();
        when(customers.checkEligibility(identity, command.now()))
                .thenReturn(new CustomerLoginEligibilityResult.Unavailable());

        assertThat(service.confirm(command))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE));
        verify(owners, never()).accept(any(), any(), any());
    }

    @Test
    void rejectedCustomerCannotReachDurableOwnerAcceptance() {
        passwordVerifies();
        when(customers.checkEligibility(identity, command.now()))
                .thenReturn(new CustomerLoginEligibilityResult.Rejected());

        assertThat(service.confirm(command))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));
        verifyNoInteractions(owners);
    }

    @Test
    void skippedBlockWatermarkDoesNotBecomeAccepted() {
        assertThat(ownerAnswers(new CustomerOwnerAcceptance.ReconciliationRequired()))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));
    }

    @Test
    void unreachableOwnerStoreIsUnavailableAndNotRejected() {
        passwordVerifies();
        when(customers.checkEligibility(identity, command.now()))
                .thenReturn(new CustomerLoginEligibilityResult.Eligible(customer));
        when(owners.accept(identity, customer, "test-policy"))
                .thenThrow(new CustomerOwnerUnavailableException(new RuntimeException("down")));

        assertThat(service.confirm(command))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.UNAVAILABLE));
    }

    /**
     * Pins today's behaviour, which is also the open question: PasswordLoginResult.Conflict is
     * published as 409 STATE_CONFLICT but has no producer, so an owner conflict is answered with
     * the same REJECTED as a wrong password. Change this test only together with that decision.
     */
    @Test
    void ownerConflictIsAnsweredAsRejectedToday() {
        assertThat(ownerAnswers(new CustomerOwnerAcceptance.Conflict()))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));
    }

    /** Same open question as {@link #ownerConflictIsAnsweredAsRejectedToday()}. */
    @Test
    void notClaimableOwnerIsAnsweredAsRejectedToday() {
        assertThat(ownerAnswers(new CustomerOwnerAcceptance.NotClaimable()))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));
    }

    @Test
    void rejectedOwnerIsRejected() {
        assertThat(ownerAnswers(new CustomerOwnerAcceptance.Rejected()))
                .isEqualTo(new PasswordIdentityResult.Denied(LoginDenial.REJECTED));
    }

    private PasswordIdentityResult ownerAnswers(CustomerOwnerAcceptance acceptance) {
        passwordVerifies();
        when(customers.checkEligibility(identity, command.now()))
                .thenReturn(new CustomerLoginEligibilityResult.Eligible(customer));
        when(owners.accept(identity, customer, "test-policy")).thenReturn(acceptance);
        return service.confirm(command);
    }

    private void passwordVerifies() {
        when(passwords.verify(command.credential()))
                .thenReturn(new PasswordVerificationOutcome.Verified(identity));
    }

    private static PasswordLoginCommand command() {
        Instant now = Instant.parse("2026-10-13T00:00:00Z");
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "public-jwk");
        return new PasswordLoginCommand(new PasswordOperationContext(UUID.randomUUID(),
                "neo-mobile", "ANDROID", "installation-1234567890", "alice", null),
                new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", null, "recipient-key"),
                now, now.plusSeconds(8), now.plusSeconds(900));
    }
}
