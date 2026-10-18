package com.vpbank.dcp.infrastructure.config;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.application.trusteddevice.TrustedDeviceService;
import com.vpbank.dcp.core.application.trusteddevice.TrustedDeviceSessions;
import com.vpbank.dcp.core.application.trusteddevice.TrustedSessionIssuer;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.mfa.MfaTransactions;
import com.vpbank.dcp.core.port.out.trusteddevice.BffCallerAssertions;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionCryptography;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStore;
import com.vpbank.dcp.core.port.out.trusteddevice.ServerKeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceRecords;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.TrustedDeviceResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BffAssertionVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.JcsCommandDigest;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.LengthPrefixedSigningInputEncoder;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.MfaReceiptVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.RestrictedSessionCryptoAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ServerKeyExchangeAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ServerKeyWrappingKeys;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import com.vpbank.dcp.infrastructure.adapter.out.http.InvalidExternalHttpSettingsException;
import com.vpbank.dcp.infrastructure.adapter.out.mfa.MfaHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.mfa.MfaHttpEndpoints;
import com.vpbank.dcp.infrastructure.adapter.out.mfa.MfaTransactionsAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisAssertionReplay;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisRestrictedSessionStore;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.config.properties.TrustedDeviceProperties;
import com.vpbank.dcp.infrastructure.persistence.adapter.JpaTrustedDeviceRecords;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceActivationPersistenceRepository;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Integration-only trusted-device continuation, gated exactly like the password login slice. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@EnableConfigurationProperties(TrustedDeviceProperties.class)
public class TrustedDeviceConfiguration {
    /** The trust is proven by FACE at the MFA service (draft doc 20 §4 confirm). */
    private static final String TRUST_METHOD = "MFA_FACE";
    private static final int MAX_MFA_RESPONSE_BYTES = 8192;

    @Bean
    RestrictedSessionCryptography restrictedSessionCryptography(
            BankingTokenEnvelopeIssuer envelopes, LengthPrefixedSigningInputEncoder encoding,
            Sha256Digests digests, BankingTokenIssuer tokens) {
        return new RestrictedSessionCryptoAdapter(tokens, envelopes, encoding, digests);
    }

    @Bean
    RestrictedSessionStore restrictedSessionStore(StringRedisTemplate redis,
                                                  RedisServerIdentity identity, Clock clock) {
        return new RedisRestrictedSessionStore(redis, identity, clock);
    }

    @Bean
    TrustedDeviceSessions trustedDeviceSessions(RestrictedSessionCryptography cryptography,
                                                RestrictedSessionStore store,
                                                TrustedDeviceProperties properties) {
        return new TrustedDeviceSessions(cryptography, store,
                Duration.ofSeconds(properties.restrictedSessionTtlSeconds()));
    }

    @Bean
    ServerKeyExchange serverKeyExchange(TrustedDeviceProperties properties, StrictJoseJson json,
                                        Sha256Digests digests,
                                        LengthPrefixedSigningInputEncoder encoding,
                                        SecureRandom random) {
        var wrapping = properties.serverKeyWrapping();
        Map<String, byte[]> keys = new HashMap<>();
        try {
            wrapping.keysBase64().forEach((id, key) -> keys.put(id, Base64.getDecoder().decode(key)));
            return new ServerKeyExchangeAdapter(new ServerKeyWrappingKeys(wrapping.activeKeyId(), keys),
                    json, digests, encoding, random);
        } catch (IllegalArgumentException failure) {
            throw new InvalidLoginIntegrationConfigurationException(failure);
        } finally {
            keys.values().forEach(key -> Arrays.fill(key, (byte) 0));
        }
    }

    @Bean
    MfaTransactions mfaTransactions(HttpClient workloadHttpClient, TrustedDeviceProperties properties,
                                    StrictJoseJson strictJson, Sha256Digests digests,
                                    JcsCommandDigest canonicalDigest, JsonMapper json, Clock clock) {
        var mfa = properties.mfa();
        try {
            ExternalHttpClient http = new ExternalHttpClient(workloadHttpClient,
                    new ExternalHttpSettings(URI.create(mfa.origin()),
                            Duration.ofMillis(mfa.requestTimeoutMs()), MAX_MFA_RESPONSE_BYTES,
                            MfaHttpEndpoints.allowedRoutes()));
            MfaReceiptVerifier receipts = new MfaReceiptVerifier(mfa.receipt().issuer(),
                    mfa.receipt().keyId(), ECKey.parse(mfa.receipt().publicJwk()), strictJson, digests);
            return new MfaTransactionsAdapter(new MfaHttpClient(http), receipts, canonicalDigest,
                    json, clock);
        } catch (InvalidExternalHttpSettingsException | ParseException
                 | IllegalArgumentException failure) {
            throw new InvalidLoginIntegrationConfigurationException(failure);
        }
    }

    @Bean
    TrustedDeviceRecords trustedDeviceRecords(TrustedDeviceActivationPersistenceRepository devices,
                                              SecurityAuditJpaRepository audit,
                                              DeviceIdCodec deviceIds,
                                              TransactionTemplate transactions, Clock clock,
                                              TrustedDeviceProperties properties) {
        return new JpaTrustedDeviceRecords(devices, audit, deviceIds, transactions, clock,
                new JpaTrustedDeviceRecords.TrustPolicy(
                        Duration.ofDays(properties.trustLifetimeDays()),
                        properties.maximumActiveDevices(), TRUST_METHOD,
                        properties.trustPolicyVersion()));
    }

    @Bean
    TrustedDeviceUseCase trustedDeviceUseCase(TrustedDeviceSessions sessions, ServerKeyExchange keys,
                                              MfaTransactions mfa, TrustedDeviceRecords records,
                                              CustomerDirectory customers,
                                              LoginDeviceRepository devices,
                                              IssueLoginSessionUseCase issuance,
                                              TrustedDeviceProperties properties) {
        return new TrustedDeviceService(sessions, keys, mfa, records,
                new TrustedSessionIssuer(customers, devices, issuance),
                properties.verifyMaxAttempts());
    }

    @Bean
    BffCallerAssertions bffCallerAssertions(TrustedDeviceProperties properties,
                                            StrictJoseJson strictJson, Sha256Digests digests,
                                            StringRedisTemplate redis, AuthorityScope scope,
                                            Clock clock) {
        var bff = properties.bffAssertion();
        try {
            return new BffAssertionVerifier(bff.issuer(), bff.keyId(), ECKey.parse(bff.publicJwk()),
                    strictJson, digests, new RedisAssertionReplay(redis, new ReplayKeys(scope), clock));
        } catch (InvalidCryptographicInputException | ParseException failure) {
            throw new InvalidLoginIntegrationConfigurationException(failure);
        }
    }

    @Bean
    TrustedDeviceResponseMapper trustedDeviceResponseMapper(PasswordLoginResponseMapper sessions,
                                                            JsonMapper json) {
        return new TrustedDeviceResponseMapper(sessions, json);
    }
}
