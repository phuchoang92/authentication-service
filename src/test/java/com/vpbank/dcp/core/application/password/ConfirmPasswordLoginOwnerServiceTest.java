package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ConfirmPasswordLoginOwnerServiceTest {

    private final CheckCustomerLoginEligibilityService snapshots = mock(CheckCustomerLoginEligibilityService.class);
    private final CustomerOwnerRepository owners = mock(CustomerOwnerRepository.class);
    private final ConfirmPasswordLoginOwnerService service =
            new ConfirmPasswordLoginOwnerService(snapshots, owners, "test-policy");
    private final UUID operationId = UUID.randomUUID();
    private final VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
            "https://auth.bank.test/realms/mobile", "kc-a");
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");
    private final CustomerAuthenticationState customer = new CustomerAuthenticationState(
            "CUST-1", CustomerStatus.ELIGIBLE, 1, 0, now);

    @Test
    void eligibleSnapshotAndDurableOwnerAreBothRequired() {
        UUID subjectId = UUID.randomUUID();
        when(snapshots.checkEligibility(identity, now))
                .thenReturn(new CustomerLoginEligibilityResult.Eligible(customer));
        when(owners.accept(operationId, "neo-mobile", identity, customer, "test-policy"))
                .thenReturn(new CustomerOwnerAcceptance.Accepted(subjectId));

        assertThat(service.confirmOwner(operationId, "neo-mobile", identity, now))
                .isEqualTo(new PasswordLoginOwnerResult.Accepted(subjectId, customer));
        verify(owners).accept(operationId, "neo-mobile", identity, customer, "test-policy");
    }

    @Test
    void unavailableCustomerNeverTouchesOwnerStore() {
        when(snapshots.checkEligibility(identity, now)).thenReturn(new CustomerLoginEligibilityResult.Unavailable());

        assertThat(service.confirmOwner(operationId, "neo-mobile", identity, now))
                .isInstanceOf(PasswordLoginOwnerResult.Unavailable.class);
        verify(owners, never()).accept(operationId, "neo-mobile", identity, customer, "test-policy");
    }

    @Test
    void skippedBlockWatermarkDoesNotBecomeAccepted() {
        when(snapshots.checkEligibility(identity, now))
                .thenReturn(new CustomerLoginEligibilityResult.Eligible(customer));
        when(owners.accept(operationId, "neo-mobile", identity, customer, "test-policy"))
                .thenReturn(new CustomerOwnerAcceptance.ReconciliationRequired());

        assertThat(service.confirmOwner(operationId, "neo-mobile", identity, now))
                .isInstanceOf(PasswordLoginOwnerResult.Rejected.class);
    }
}
