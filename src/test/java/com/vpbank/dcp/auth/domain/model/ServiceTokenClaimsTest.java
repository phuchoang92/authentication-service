package com.vpbank.dcp.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ServiceTokenClaimsTest {
    private static final Instant T0 = Instant.parse("2026-11-03T10:00:00Z");
    private static final ServiceId ONBOARDING_SERVICE = new ServiceId("onboarding-service");

    @Test
    void serviceIdAndBusinessReferenceAcceptTheContractFormatsOnly() {
        assertThat(new ServiceId("onboarding-service").value()).isEqualTo("onboarding-service");
        assertThat(new BusinessReference("onb-2026:0001").value()).isEqualTo("onb-2026:0001");

        assertThatThrownBy(() -> new ServiceId("Onboarding")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ServiceId("ab")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ServiceId("a b")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BusinessReference("")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BusinessReference("has space")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BusinessReference("x".repeat(129))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ServiceId(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void claimsHoldTogether() {
        ServiceTokenClaims claims = onboardingClaims().build();

        assertThat(claims.caller()).isEqualTo(ONBOARDING_SERVICE);
        assertThat(claims.scope()).isEqualTo(ServiceScope.ONBOARDING);
        assertThat(claims.businessReference()).isEqualTo(new BusinessReference("onb-1"));
    }

    @Test
    void claimsRejectAnExpiryBeforeIssueAndAScopeWithoutItsReference() {
        assertThatThrownBy(() -> onboardingClaims().expiresAt(T0).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> onboardingClaims().businessReference(null).build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> onboardingClaims().issuer(" ").build())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> onboardingClaims().tokenId(null).build())
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void grantsAnswerPerCallerAndScopeAndAreCopied() {
        Set<ServiceScope> scopes = new HashSet<>(Set.of(ServiceScope.ONBOARDING));
        Map<ServiceId, Set<ServiceScope>> source = new HashMap<>(Map.of(ONBOARDING_SERVICE, scopes));
        ServiceScopeGrants grants = new ServiceScopeGrants(source);

        scopes.clear();
        source.clear();

        assertThat(grants.allows(ONBOARDING_SERVICE, ServiceScope.ONBOARDING)).isTrue();
        assertThat(grants.allows(new ServiceId("account-service"), ServiceScope.ONBOARDING)).isFalse();
        assertThatThrownBy(() -> grants.grants().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    private static ServiceTokenClaims.ServiceTokenClaimsBuilder onboardingClaims() {
        return ServiceTokenClaims.builder()
                .issuer("authentication-service")
                .caller(ONBOARDING_SERVICE)
                .audience("mobile-bff")
                .scope(ServiceScope.ONBOARDING)
                .businessReference(new BusinessReference("onb-1"))
                .issuedAt(T0)
                .expiresAt(T0.plus(Duration.ofMinutes(15)))
                .tokenId(UUID.fromString("00000000-0000-4000-8000-000000000001"));
    }
}
