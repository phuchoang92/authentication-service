package com.vpbank.dcp.core.customer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class CheckCustomerLoginEligibilityServiceTest {

    private final CustomerDirectory directory = mock(CustomerDirectory.class);
    private final CheckCustomerLoginEligibilityService service =
            new CheckCustomerLoginEligibilityService(directory, Duration.ofSeconds(30));
    private final VerifiedProviderIdentity identity = new VerifiedProviderIdentity(
            "https://auth.bank.test/realms/mobile", "kc-user-1");
    private final Instant now = Instant.parse("2026-10-11T10:00:00Z");

    @Test
    void eligibleFreshSnapshotCanContinueToLocalGuardChecks() {
        CustomerAuthenticationState customer = customer(CustomerStatus.ELIGIBLE, now);
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(customer));
        assertThat(service.checkEligibility(identity, now))
                .isEqualTo(new CustomerLoginEligibilityResult.Eligible(customer));
    }

    @Test
    void snapshotExpiresAtTheExactFreshnessBoundary() {
        CustomerAuthenticationState customer = customer(CustomerStatus.ELIGIBLE, now);
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(customer));
        assertThat(service.checkEligibility(identity, now.plusSeconds(30).minusNanos(1)))
                .isInstanceOf(CustomerLoginEligibilityResult.Eligible.class);
        assertThat(service.checkEligibility(identity, now.plusSeconds(30)))
                .isInstanceOf(CustomerLoginEligibilityResult.Unavailable.class);
    }

    @Test
    void blockedCustomerAndUnknownIdentityRejectGenerically() {
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.BLOCKED, now)));
        assertThat(service.checkEligibility(identity, now))
                .isInstanceOf(CustomerLoginEligibilityResult.Rejected.class);

        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.CLOSED, now)));
        assertThat(service.checkEligibility(identity, now))
                .isInstanceOf(CustomerLoginEligibilityResult.Rejected.class);

        when(directory.resolve(identity)).thenReturn(new CustomerResolution.NotFound());
        assertThat(service.checkEligibility(identity, now))
                .isInstanceOf(CustomerLoginEligibilityResult.Rejected.class);
    }

    @Test
    void staleFutureOrUnavailableSnapshotCannotAuthorizeLogin() {
        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.ELIGIBLE, now.minusSeconds(31))));
        assertThat(service.checkEligibility(identity, now))
                .isInstanceOf(CustomerLoginEligibilityResult.Unavailable.class);

        when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(
                customer(CustomerStatus.ELIGIBLE, now.plusSeconds(1))));
        assertThat(service.checkEligibility(identity, now))
                .isInstanceOf(CustomerLoginEligibilityResult.Unavailable.class);

        when(directory.resolve(identity)).thenThrow(new CustomerDirectoryUnavailableException());
        assertThat(service.checkEligibility(identity, now))
                .isInstanceOf(CustomerLoginEligibilityResult.Unavailable.class);
    }

    @Test
    void missingFreshnessPolicyFailsConstruction() {
        assertThatThrownBy(() -> new CheckCustomerLoginEligibilityService(directory, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private CustomerAuthenticationState customer(CustomerStatus status, Instant checkedAt) {
        long blockVersion = status == CustomerStatus.ELIGIBLE ? 0 : 1;
        return new CustomerAuthenticationState(new CustomerNumber("CUST-001"), status, 1, blockVersion, checkedAt);
    }
}
