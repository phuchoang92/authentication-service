package com.vpbank.dcp.core.application.password;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.InvalidCustomerFreshnessPolicyException;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectoryUnavailableException;
import com.vpbank.dcp.core.port.out.customer.CustomerResolution;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class CustomerSnapshotCheckServiceTest {

    private final CustomerDirectory directory = mock(CustomerDirectory.class);
    private final CustomerSnapshotCheckService service =
            new CustomerSnapshotCheckService(directory, Duration.ofSeconds(30));
    private final VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
            "https://auth.bank.test/realms/mobile", "kc-user-1");
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");

    @Test
    void eligibleFreshSnapshotCanContinueToLocalGuardChecks() {
        CustomerAuthenticationState customer = customer(CustomerStatus.ELIGIBLE, now);
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(customer));
        assertThat(service.check(identity, now))
                .isEqualTo(new CustomerSnapshotCheckResult.Eligible(customer));
    }

    @Test
    void blockedCustomerAndUnknownIdentityRejectGenerically() {
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.BLOCKED, now)));
        assertThat(service.check(identity, now))
                .isInstanceOf(CustomerSnapshotCheckResult.Rejected.class);

        when(directory.resolve(identity)).thenReturn(new CustomerResolution.NotFound());
        assertThat(service.check(identity, now))
                .isInstanceOf(CustomerSnapshotCheckResult.Rejected.class);
    }

    @Test
    void staleFutureOrUnavailableSnapshotCannotAuthorizeLogin() {
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.ELIGIBLE, now.minusSeconds(31))));
        assertThat(service.check(identity, now))
                .isInstanceOf(CustomerSnapshotCheckResult.Unavailable.class);

        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.ELIGIBLE, now.plusSeconds(1))));
        assertThat(service.check(identity, now))
                .isInstanceOf(CustomerSnapshotCheckResult.Unavailable.class);

        when(directory.resolve(identity)).thenThrow(new CustomerDirectoryUnavailableException());
        assertThat(service.check(identity, now))
                .isInstanceOf(CustomerSnapshotCheckResult.Unavailable.class);
    }

    @Test
    void missingFreshnessPolicyFailsConstruction() {
        assertThatThrownBy(() -> new CustomerSnapshotCheckService(directory, Duration.ZERO))
                .isInstanceOf(InvalidCustomerFreshnessPolicyException.class);
    }

    private CustomerAuthenticationState customer(CustomerStatus status, Instant checkedAt) {
        long blockVersion = status == CustomerStatus.ELIGIBLE ? 0 : 1;
        return new CustomerAuthenticationState("CUST-001", status, 1, blockVersion, checkedAt);
    }
}
