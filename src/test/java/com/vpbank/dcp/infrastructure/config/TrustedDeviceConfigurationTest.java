package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.core.session.TrustedDeviceSessions;
import com.vpbank.dcp.core.session.IssueLoginSessionService;
import com.vpbank.dcp.core.trusteddevice.TrustedDeviceService;
import com.vpbank.dcp.core.customer.CustomerDirectory;
import com.vpbank.dcp.core.device.LoginDeviceRepository;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.core.trusteddevice.BffCallerAssertions;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.JcsCommandDigest;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceActivationPersistenceRepository;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

class TrustedDeviceConfigurationTest {
    private static final String PUBLIC_JWK = publicJwk();
    private static final String[] ACTIVE = {
            "spring.profiles.active=integration",
            "auth.native-session.integration-activation-enabled=true",
            "auth.trusted-device.restricted-session-ttl-seconds=600",
            "auth.trusted-device.verify-max-attempts=3",
            "auth.trusted-device.trust-lifetime-days=90",
            "auth.trusted-device.maximum-active-devices=3",
            "auth.trusted-device.trust-policy-version=trust-v1",
            "auth.trusted-device.server-key-wrapping.active-key-id=w1",
            "auth.trusted-device.server-key-wrapping.keys-base64.w1="
                    + Base64.getEncoder().encodeToString(new byte[32]),
            "auth.trusted-device.bff-assertion.issuer=mobile-bff",
            "auth.trusted-device.bff-assertion.key-id=bff-v1",
            "auth.trusted-device.bff-assertion.public-jwk=" + PUBLIC_JWK,
            "auth.trusted-device.mfa.origin=https://mfa.bank.test",
            "auth.trusted-device.mfa.request-timeout-ms=3000",
            "auth.trusted-device.mfa.receipt.issuer=mfa-service",
            "auth.trusted-device.mfa.receipt.key-id=mfa-v1",
            "auth.trusted-device.mfa.receipt.public-jwk=" + PUBLIC_JWK};

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withUserConfiguration(TrustedDeviceConfiguration.class)
            .withBean(BankingTokenEnvelopeIssuer.class, () -> mock(BankingTokenEnvelopeIssuer.class))
            .withBean(LengthPrefixedSigningInputEncoder.class, LengthPrefixedSigningInputEncoder::new)
            .withBean(Sha256Digests.class, Sha256Digests::new)
            .withBean(StrictJoseJson.class, StrictJoseJson::new)
            .withBean(JcsCommandDigest.class,
                    () -> new JcsCommandDigest(new StrictJoseJson(), new Sha256Digests()))
            .withBean(JsonMapper.class, JsonMapper::new)
            .withBean(BankingTokenIssuer.class,
                    () -> new BankingTokenIssuer(new SecureRandom(), new Sha256Digests()))
            .withBean(SecureRandom.class, SecureRandom::new)
            .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
            .withBean(RedisServerIdentity.class, () -> mock(RedisServerIdentity.class))
            .withBean(AuthorityScope.class, () -> new AuthorityScope("bank-test"))
            .withBean(HttpClient.class, HttpClient::newHttpClient)
            .withBean(TrustedDeviceActivationPersistenceRepository.class,
                    () -> mock(TrustedDeviceActivationPersistenceRepository.class))
            .withBean(SecurityAuditJpaRepository.class, () -> mock(SecurityAuditJpaRepository.class))
            .withBean(DeviceIdCodec.class, () -> mock(DeviceIdCodec.class))
            .withBean(TransactionTemplate.class, () -> mock(TransactionTemplate.class))
            .withBean(CustomerDirectory.class, () -> mock(CustomerDirectory.class))
            .withBean(LoginDeviceRepository.class, () -> mock(LoginDeviceRepository.class))
            .withBean(IssueLoginSessionService.class, () -> mock(IssueLoginSessionService.class))
            .withBean(PasswordLoginResponseMapper.class,
                    () -> new PasswordLoginResponseMapper(Clock.systemUTC()))
            .withBean(Clock.class, Clock::systemUTC);

    @Test
    void integrationActivationWiresTheTrustedDeviceSteps() {
        runner.withPropertyValues(ACTIVE)
                .run(context -> assertThat(context).hasNotFailed()
                        .hasSingleBean(TrustedDeviceSessions.class)
                        .hasSingleBean(TrustedDeviceService.class)
                        .hasSingleBean(BffCallerAssertions.class));
    }

    @Test
    void lifetimeOutsideTheAllowedRangeStopsStartup() {
        runner.withPropertyValues(ACTIVE)
                .withPropertyValues("auth.trusted-device.restricted-session-ttl-seconds=30")
                .run(context -> assertThat(context).hasFailed());
    }

    /** The device limit is bank policy: no value means no startup, never a silent default. */
    @Test
    void missingDeviceLimitStopsStartup() {
        runner.withPropertyValues(ACTIVE)
                .withPropertyValues("auth.trusted-device.maximum-active-devices=")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void wrappingKeyOfTheWrongSizeStopsStartup() {
        runner.withPropertyValues(ACTIVE)
                .withPropertyValues("auth.trusted-device.server-key-wrapping.keys-base64.w1="
                        + Base64.getEncoder().encodeToString(new byte[16]))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void withoutIntegrationActivationNothingIsExposed() {
        runner.withPropertyValues("auth.trusted-device.restricted-session-ttl-seconds=600")
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean(TrustedDeviceSessions.class)
                        .doesNotHaveBean(TrustedDeviceService.class));
    }

    private static String publicJwk() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }
}
