package com.vpbank.dcp.auth.domain.enums;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The {@code scope} claim values are a wire contract with the BFF; this list is frozen. */
class ServiceScopeTest {

    @Test
    void wireCodesAreFrozen() {
        assertThat(ServiceScope.ONBOARDING.code()).isEqualTo("onboarding");
        assertThat(ServiceScope.ONBOARDING.businessReferenceRequired()).isTrue();
    }

    @Test
    void parsingIsExactAndFailsClosed() {
        assertThat(ServiceScope.fromCode("onboarding")).contains(ServiceScope.ONBOARDING);
        assertThat(ServiceScope.fromCode("ONBOARDING")).isEmpty();
        assertThat(ServiceScope.fromCode(" onboarding")).isEmpty();
        assertThat(ServiceScope.fromCode("banking")).isEmpty();
        assertThat(ServiceScope.fromCode(null)).isEmpty();
    }
}
