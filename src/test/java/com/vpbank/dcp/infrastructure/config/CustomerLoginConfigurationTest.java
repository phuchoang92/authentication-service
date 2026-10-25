package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.customer.CustomerNumber;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.customer.CustomerStatus;
import com.vpbank.dcp.core.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.customer.CheckCustomerLoginEligibilityService;
import com.vpbank.dcp.core.customer.CustomerLoginEligibilityResult;
import com.vpbank.dcp.core.customer.CustomerDirectory;
import com.vpbank.dcp.core.customer.CustomerResolution;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

class CustomerLoginConfigurationTest {
    private final CustomerDirectory directory = mock(CustomerDirectory.class);
    private final WebApplicationContextRunner context = new WebApplicationContextRunner()
            .withUserConfiguration(CustomerLoginConfiguration.class)
            .withBean(CustomerDirectory.class, () -> directory);

    @Test
    void assemblesTheSharedUseCaseWithCustomerFreshnessConfiguration() {
        context.withPropertyValues("auth.customer.status-max-age-ms=1000").run(started -> {
            assertThat(started).hasNotFailed().hasSingleBean(CheckCustomerLoginEligibilityService.class)
                    .doesNotHaveBean(PasswordFlowProperties.class);
            verifyNoInteractions(directory);
            var identity = new VerifiedProviderIdentity("https://auth.bank.test/realms/mobile", "kc-a");
            Instant checkedAt = Instant.parse("2026-10-13T00:00:00Z");
            var customer = new CustomerAuthenticationState(new CustomerNumber("CUST-1"), CustomerStatus.ELIGIBLE, 1, 0, checkedAt);
            when(directory.resolve(identity)).thenReturn(new CustomerResolution.Found(customer));
            var customers = started.getBean(CheckCustomerLoginEligibilityService.class);
            assertThat(customers.checkEligibility(identity, checkedAt.plusMillis(999)))
                    .isEqualTo(new CustomerLoginEligibilityResult.Eligible(customer));
            assertThat(customers.checkEligibility(identity, checkedAt.plusMillis(1000)))
                    .isInstanceOf(CustomerLoginEligibilityResult.Unavailable.class);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "auth.customer.status-max-age-ms=0", "auth.customer.status-max-age-ms=-1"})
    void missingOrNonPositiveFreshnessNeverStartsTheUseCase(String property) {
        var configured = property.isEmpty() ? context : context.withPropertyValues(property);
        configured.run(started -> {
            assertThat(started).hasFailed();
            verifyNoInteractions(directory);
        });
    }
}
