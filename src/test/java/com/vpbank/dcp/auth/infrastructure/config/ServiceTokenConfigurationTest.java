package com.vpbank.dcp.auth.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.in.IssueServiceTokenUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.ServiceTokenSigner;
import com.vpbank.dcp.auth.application.service.ServiceTokenSettings;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.domain.model.ServiceScopeGrants;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceTokenPublicKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller.ServiceTokenController;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller.ServiceTokenJwksController;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

class ServiceTokenConfigurationTest {
    private static final ECKey SIGNING_KEY = generate("svc-2026-1");
    private static final ECKey ONBOARDING_KEY = generate("onboarding-1");
    private static final String[] ENABLED = {
            "auth.service-token.enabled=true",
            "auth.service-token.lifetime=PT15M",
            "auth.service-token.signing-private-jwk=" + SIGNING_KEY.toJSONString(),
            "auth.service-token.callers.onboarding-service.public-jwk=" + ONBOARDING_KEY.toPublicJWK().toJSONString(),
            "auth.service-token.callers.onboarding-service.scopes[0]=onboarding"};

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withUserConfiguration(RestConfiguration.class, ServiceTokenConfiguration.class,
                    ServiceTokenController.class, ServiceTokenJwksController.class)
            .withBean(StringRedisTemplate.class, () -> Mockito.mock(StringRedisTemplate.class));

    @Test
    void offByDefaultSoNoRouteFilterOrSignerExists() {
        runner.run(context -> assertThat(context).hasNotFailed()
                .doesNotHaveBean(IssueServiceTokenUseCase.class).doesNotHaveBean(ServiceTokenSigner.class)
                .doesNotHaveBean(ServiceClientAssertionFilter.class).doesNotHaveBean(ServiceTokenController.class)
                .doesNotHaveBean(ServiceTokenJwksController.class));
    }

    @Test
    void onWithEverySettingWiresTheRoutesTheGateAndTheGrants() {
        runner.withPropertyValues(ENABLED).run(context -> {
            assertThat(context).hasNotFailed()
                    .hasSingleBean(IssueServiceTokenUseCase.class).hasSingleBean(ServiceTokenSigner.class)
                    .hasSingleBean(ServiceClientAssertionFilter.class).hasSingleBean(ServiceTokenController.class)
                    .hasSingleBean(ServiceTokenJwksController.class);
            assertThat(context.getBean(ServiceTokenSettings.class))
                    .isEqualTo(new ServiceTokenSettings("authentication-service", "mobile-bff", Duration.ofMinutes(15)));
            assertThat(context.getBean(ServiceScopeGrants.class).allows(new ServiceId("onboarding-service"), ServiceScope.ONBOARDING)).isTrue();
            assertThat(context.getBean(ServiceTokenPublicKeys.class).json()).contains("\"kid\":\"svc-2026-1\"").doesNotContain("\"d\"");
        });
    }

    @Test
    void theLifetimeIsRequiredAndBounded() {
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.service-token.lifetime=")
                .run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.service-token.lifetime=PT31M")
                .run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.service-token.lifetime=PT30S")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void aBadSigningKeyStopsStartupNamingTheSetting() {
        for (String badKey : new String[] {
                SIGNING_KEY.toPublicJWK().toJSONString(),                       // public only
                generate(null).toJSONString(),                                  // no kid
                "{\"kty\":\"oct\"}"}) {
            runner.withPropertyValues(ENABLED).withPropertyValues("auth.service-token.signing-private-jwk=" + badKey)
                    .run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("auth.service-token.signing-private-jwk");
                    });
        }
    }

    @Test
    void aBadCallerEntryStopsStartupNamingTheSetting() {
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.service-token.callers.onboarding-service.scopes[0]=banking")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("auth.service-token.callers.onboarding-service.scopes");
                });
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.service-token.callers.onboarding-service.public-jwk=" + ONBOARDING_KEY.toJSONString())
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause()
                            .hasMessageContaining("auth.service-token.callers.onboarding-service.public-jwk");
                });
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.service-token.callers.onboarding-service.public-jwk=" + generate(null).toPublicJWK().toJSONString())
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("has no kid");
                });
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.service-token.callers.Onboarding.public-jwk=" + ONBOARDING_KEY.toPublicJWK().toJSONString(),
                        "auth.service-token.callers.Onboarding.scopes[0]=onboarding")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("is not a service ID");
                });
    }

    private static ECKey generate(String keyId) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }
}
