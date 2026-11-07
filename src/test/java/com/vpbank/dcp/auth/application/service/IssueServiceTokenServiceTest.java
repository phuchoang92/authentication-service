package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.port.out.gateway.ServiceTokenSigner;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.domain.model.ServiceScopeGrants;
import com.vpbank.dcp.auth.domain.model.ServiceTokenClaims;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IssueServiceTokenServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-03T10:00:00Z");
    private static final UUID TOKEN_ID = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final ServiceId ONBOARDING_SERVICE = new ServiceId("onboarding-service");
    private static final ServiceId ACCOUNT_SERVICE = new ServiceId("account-service");

    /** Test double: remembers what it was asked to sign and answers with a token naming the ID. */
    private static final class RecordingSigner implements ServiceTokenSigner {
        final List<ServiceTokenClaims> signed = new ArrayList<>();

        @Override
        public String sign(ServiceTokenClaims claims) {
            signed.add(claims);
            return "signed:" + claims.tokenId();
        }
    }

    private final RecordingSigner signer = new RecordingSigner();
    private final RecordingSecurityAuditStore audit = new RecordingSecurityAuditStore();
    private final ServiceTokenSettings settings = new ServiceTokenSettings("authentication-service", "mobile-bff",
            Duration.ofMinutes(15));
    private final IssueServiceTokenService service = new IssueServiceTokenService(
            new ServiceScopeGrants(Map.of(ONBOARDING_SERVICE, Set.of(ServiceScope.ONBOARDING))),
            signer,
            () -> TOKEN_ID,
            settings,
            audit,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aGrantedCallerGetsATokenWithExactlyTheSettingsTheScopeAndItsReference() {
        IssueServiceTokenResult result = service.issue(
                new IssueServiceTokenCommand(ONBOARDING_SERVICE, ServiceScope.ONBOARDING, new BusinessReference("onb-1")));

        assertThat(result).isEqualTo(new IssueServiceTokenResult.Issued("signed:" + TOKEN_ID, ServiceScope.ONBOARDING,
                NOW.plus(Duration.ofMinutes(15))));
        assertThat(signer.signed).containsExactly(ServiceTokenClaims.builder()
                .issuer("authentication-service")
                .issuedTo(ONBOARDING_SERVICE)
                .audience("mobile-bff")
                .scope(ServiceScope.ONBOARDING)
                .businessReference(new BusinessReference("onb-1"))
                .issuedAt(NOW)
                .expiresAt(NOW.plus(Duration.ofMinutes(15)))
                .tokenId(TOKEN_ID)
                .build());
        assertThat(result.toString()).doesNotContain("signed:");
        assertThat(audit.only().reason()).isEqualTo(SecurityEventReason.TOKEN_ISSUED);
        assertThat(audit.only().serviceId()).isEqualTo(ONBOARDING_SERVICE);
        assertThat(audit.only().scope()).isEqualTo(ServiceScope.ONBOARDING);
        assertThat(audit.only().tokenId()).isEqualTo(TOKEN_ID);
        assertThat(audit.only().occurredAt()).isEqualTo(NOW);
        assertThat(audit.only().channel()).isNull();
    }

    @Test
    void aCallerWithoutTheScopeIsRefusedBeforeAnythingIsSigned() {
        IssueServiceTokenResult result = service.issue(
                new IssueServiceTokenCommand(ACCOUNT_SERVICE, ServiceScope.ONBOARDING, new BusinessReference("onb-1")));

        assertThat(result).isInstanceOf(IssueServiceTokenResult.ScopeNotAllowed.class);
        assertThat(signer.signed).isEmpty();
        assertThat(audit.only().reason()).isEqualTo(SecurityEventReason.SCOPE_NOT_GRANTED);
        assertThat(audit.only().serviceId()).isEqualTo(ACCOUNT_SERVICE);
        assertThat(audit.only().tokenId()).isNull();
    }

    @Test
    void onboardingWithoutAnOnboardingRequestIsRefused() {
        IssueServiceTokenResult result = service.issue(
                new IssueServiceTokenCommand(ONBOARDING_SERVICE, ServiceScope.ONBOARDING, null));

        assertThat(result).isInstanceOf(IssueServiceTokenResult.BusinessReferenceRequired.class);
        assertThat(signer.signed).isEmpty();
        assertThat(audit.only().reason()).isEqualTo(SecurityEventReason.BUSINESS_REFERENCE_MISSING);
    }
}
