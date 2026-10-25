package com.vpbank.dcp.auth.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller.LoginController;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.DeviceEnrollmentJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.PrimaryTrustedDeviceJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceAuditJpaRepository;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.TrustedDeviceJpaRepository;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

class LoginConfigurationTest {
    /** A fixed public P-256 JWK (RFC 7517 example key), good enough to pin at startup. */
    private static final String MFA_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"kid\":\"mfa-receipt-1\"}";
    private static final String[] ENABLED = {
            "auth.login.enabled=true",
            "auth.login.keycloak.base-url=https://kc.test",
            "auth.login.keycloak.realm=test",
            "auth.login.keycloak.client-id=authentication-service",
            "auth.login.keycloak.client-secret=secret",
            "auth.session.lookup-hmac-keys-base64.k1=" + Base64.getEncoder().encodeToString(new byte[32]),
            "auth.device.lookup-hmac-keys-base64.d1=" + Base64.getEncoder().encodeToString(new byte[32]),
            "auth.device.encryption-keys-base64.e1=" + Base64.getEncoder().encodeToString(new byte[32]),
            "auth.mfa.origin=https://mfa.test",
            "auth.mfa.receipt-issuer=mfa-service",
            "auth.mfa.receipt-public-jwk=" + MFA_KEY};

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withUserConfiguration(RestConfiguration.class, ValkeyConfiguration.class, DeviceConfiguration.class,
                    LoginConfiguration.class, LoginController.class)
            .withBean(StringRedisTemplate.class, () -> Mockito.mock(StringRedisTemplate.class))
            .withBean(CustomerAuthenticationJpaRepository.class, () -> Mockito.mock(CustomerAuthenticationJpaRepository.class))
            .withBean(TrustedDeviceJpaRepository.class, () -> Mockito.mock(TrustedDeviceJpaRepository.class))
            .withBean(PrimaryTrustedDeviceJpaRepository.class, () -> Mockito.mock(PrimaryTrustedDeviceJpaRepository.class))
            .withBean(TrustedDeviceAuditJpaRepository.class, () -> Mockito.mock(TrustedDeviceAuditJpaRepository.class))
            .withBean(DeviceEnrollmentJpaRepository.class, () -> Mockito.mock(DeviceEnrollmentJpaRepository.class));

    @Test
    void offByDefaultSoNoLoginEndpointStoreOrFilterExists() {
        runner.run(context -> assertThat(context).hasNotFailed()
                .doesNotHaveBean(LoginUseCase.class).doesNotHaveBean(SessionStore.class)
                .doesNotHaveBean(SessionFilter.class).doesNotHaveBean(LoginController.class));
    }

    @Test
    void onWithEverySettingWiresLoginSessionsAndTheFilter() {
        runner.withPropertyValues(ENABLED).run(context -> assertThat(context).hasNotFailed()
                .hasSingleBean(LoginUseCase.class).hasSingleBean(SessionStore.class)
                .hasSingleBean(IssueCaptchaUseCase.class).hasSingleBean(CaptchaStore.class)
                .hasSingleBean(TrustedDeviceRepository.class)
                .hasSingleBean(com.vpbank.dcp.auth.application.port.in.InitEnrollmentUseCase.class)
                .hasSingleBean(com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.class)
                .hasSingleBean(SessionFilter.class).hasSingleBean(LoginController.class));
    }

    @Test
    void aShortHmacKeyOrAnIssueVersionWithoutAKeyStopsStartupNamingTheSetting() {
        runner.withPropertyValues(ENABLED)
                .withPropertyValues("auth.session.lookup-hmac-keys-base64.k1=" + Base64.getEncoder().encodeToString(new byte[8]))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("lookup-hmac-keys-base64.k1");
                });
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.session.lookup-key-version=k2")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("lookup-key-version");
                });
    }

    @Test
    void aDeviceKeyIdWithoutAKeyStopsStartupNamingTheSetting() {
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.device.encryption-key-id=e9")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("e9");
                });
    }

    @Test
    void aBadMfaReceiptKeyStopsStartupNamingTheSetting() {
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.mfa.receipt-public-jwk={\"kty\":\"oct\"}")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("auth.mfa.receipt-public-jwk");
                });
    }

    @Test
    void aMissingKeycloakSettingStopsStartup() {
        runner.withPropertyValues(ENABLED).withPropertyValues("auth.login.keycloak.client-secret=")
                .run(context -> assertThat(context).hasFailed());
    }
}
