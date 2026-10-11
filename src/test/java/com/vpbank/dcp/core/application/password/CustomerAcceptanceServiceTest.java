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
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerStore;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CustomerAcceptanceServiceTest {

    private final CustomerSnapshotCheckService snapshots = mock(CustomerSnapshotCheckService.class);
    private final CustomerOwnerStore owners = mock(CustomerOwnerStore.class);
    private final CustomerAcceptanceService service =
            new CustomerAcceptanceService(snapshots, owners, "test-policy");
    private final UUID operationId = UUID.randomUUID();
    private final VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
            "https://auth.bank.test/realms/mobile", "kc-a");
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");
    private final CustomerAuthenticationState customer = new CustomerAuthenticationState(
            "CUST-1", CustomerStatus.ELIGIBLE, 1, 0, now);

    @Test
    void eligibleSnapshotAndDurableOwnerAreBothRequired() {
        UUID subjectId = UUID.randomUUID();
        when(snapshots.check(identity, now))
                .thenReturn(new CustomerSnapshotCheckResult.Eligible(customer));
        when(owners.accept(operationId, "neo-mobile", identity, customer, "test-policy"))
                .thenReturn(new CustomerOwnerAcceptance.Accepted(subjectId));

        assertThat(service.accept(operationId, "neo-mobile", identity, now))
                .isEqualTo(new CustomerAcceptanceResult.Accepted(subjectId, customer));
        verify(owners).accept(operationId, "neo-mobile", identity, customer, "test-policy");
    }

    @Test
    void unavailableCustomerNeverTouchesOwnerStore() {
        when(snapshots.check(identity, now)).thenReturn(new CustomerSnapshotCheckResult.Unavailable());

        assertThat(service.accept(operationId, "neo-mobile", identity, now))
                .isInstanceOf(CustomerAcceptanceResult.Unavailable.class);
        verify(owners, never()).accept(operationId, "neo-mobile", identity, customer, "test-policy");
    }

    @Test
    void skippedBlockWatermarkDoesNotBecomeAccepted() {
        when(snapshots.check(identity, now))
                .thenReturn(new CustomerSnapshotCheckResult.Eligible(customer));
        when(owners.accept(operationId, "neo-mobile", identity, customer, "test-policy"))
                .thenReturn(new CustomerOwnerAcceptance.ReconciliationRequired());

        assertThat(service.accept(operationId, "neo-mobile", identity, now))
                .isInstanceOf(CustomerAcceptanceResult.Rejected.class);
    }
}
