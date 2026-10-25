package com.vpbank.dcp.infrastructure.config;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.application.mfa.AdmitPendingTotpService;
import com.vpbank.dcp.core.application.mfa.CheckPendingTotpOwnerService;
import com.vpbank.dcp.core.application.mfa.CheckTotpChallengeService;
import com.vpbank.dcp.core.application.mfa.CompleteTotpLoginService;
import com.vpbank.dcp.core.application.password.StartTotpLoginService;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.totp.TotpVerificationPolicy;
import com.vpbank.dcp.core.port.in.mfa.CompleteTotpLoginUseCase;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.out.customer.CustomerDirectory;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.pending.PendingTokenCryptography;
import com.vpbank.dcp.core.port.out.pending.PendingTotpStore;
import com.vpbank.dcp.core.port.out.pending.PendingTokenLookup;
import com.vpbank.dcp.core.port.out.replay.ReplayProtection;
import com.vpbank.dcp.core.port.out.security.DpopProofDecoder;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpAvailability;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpVerifier;
import com.vpbank.dcp.core.port.out.totp.TotpProofReader;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.PendingTotpTokenCryptoAdapter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.HmacPendingTokenLookup;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.TokenLookupHasher;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPendingTotpStore;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpAlgorithm;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpProofDecryptor;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpSecretCodec;
import com.vpbank.dcp.infrastructure.adapter.out.totp.TotpSecretKeys;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.mfa.TotpLoginRequestVerifier;
import com.vpbank.dcp.infrastructure.config.properties.TotpLoginProperties;
import com.vpbank.dcp.infrastructure.persistence.adapter.JpaDeviceTotpVerifier;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceCredentialJpaRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.DeviceTotpPersistenceRepository;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

/** TOTP proof, credential verification and pending authority for isolated integration. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@EnableConfigurationProperties(TotpLoginProperties.class)
public class TotpLoginIntegrationConfiguration {

    @Bean
    PendingTokenLookup pendingTokenLookup(TokenLookupHasher lookup, LookupKeyVersion version) {
        return new HmacPendingTokenLookup(lookup, version);
    }

    @Bean
    TotpLoginRequestVerifier totpLoginRequestVerifier(PendingTokenLookup lookup, PendingTotpStore pending,
                                                      DpopProofDecoder dpop,
                                                      ExternalUriPolicy uris, Clock clock) {
        return new TotpLoginRequestVerifier(lookup, pending, dpop, uris, clock);
    }

    @Bean
    TotpSecretCodec totpSecretCodec(TotpLoginProperties properties, SecureRandom random) {
        try {
            byte[] key = Base64.getDecoder().decode(properties.secretKeyBase64());
            return new TotpSecretCodec(new TotpSecretKeys(properties.secretKeyId(),
                    Map.of(properties.secretKeyId(), key)), random);
        } catch (IllegalArgumentException failure) {
            throw new InvalidLoginIntegrationConfigurationException(failure);
        }
    }

    @Bean
    TotpProofReader totpProofReader(TotpLoginProperties properties, StrictJoseJson strict,
                                    JsonMapper json) {
        try {
            return new TotpProofDecryptor(ECKey.parse(properties.proofPrivateJwk()), strict, json);
        } catch (ParseException | IllegalArgumentException failure) {
            throw new InvalidLoginIntegrationConfigurationException(failure);
        }
    }

    @Bean
    DeviceTotpVerifier deviceTotpVerifier(DeviceTotpPersistenceRepository persistence,
                                          DeviceCredentialJpaRepository credentials,
                                          TotpSecretCodec codec, Clock clock,
                                          TransactionTemplate transactions,
                                          TotpLoginProperties properties) {
        return new JpaDeviceTotpVerifier(persistence, credentials, codec, new TotpAlgorithm(),
                new TotpVerificationPolicy(properties.maximumFailures(),
                        Duration.ofMinutes(properties.lockMinutes())), clock, transactions);
    }

    @Bean
    PendingTotpStore pendingTotpStore(StringRedisTemplate redis, RedisServerIdentity identity,
                                      JsonMapper json, Clock clock) {
        return new RedisPendingTotpStore(redis, identity, json, clock);
    }

    @Bean
    PendingTokenCryptography pendingTokenCryptography(LookupKeyVersion version,
                                                      TokenLookupHasher lookup,
                                                      BankingTokenEnvelopeIssuer envelopes,
                                                      SecureRandom random) {
        return new PendingTotpTokenCryptoAdapter(new BankingTokenIssuer(version, random),
                lookup, envelopes, version);
    }

    @Bean
    StartTotpLoginService startTotpLoginService(DeviceTotpAvailability credentials,
                                                PendingTokenCryptography cryptography,
                                                PendingTotpStore pending, SecureRandom random,
                                                TotpLoginProperties properties) {
        return new StartTotpLoginService(credentials, cryptography, pending, random,
                Duration.ofSeconds(properties.challengeLifetimeSeconds()));
    }

    @Bean
    AdmitPendingTotpService admitPendingTotpService(PendingTotpStore pending, ReplayProtection replay) {
        return new AdmitPendingTotpService(pending, replay);
    }

    @Bean
    CheckPendingTotpOwnerService checkPendingTotpOwnerService(CustomerDirectory customers,
                                                               LoginDeviceRepository devices) {
        return new CheckPendingTotpOwnerService(customers, devices);
    }

    @Bean
    CheckTotpChallengeService checkTotpChallengeService(TotpProofReader proofs,
                                                         DeviceTotpVerifier credentials) {
        return new CheckTotpChallengeService(proofs, credentials);
    }

    @Bean
    CompleteTotpLoginUseCase completeTotpLoginUseCase(AdmitPendingTotpService admission,
                                                      CheckPendingTotpOwnerService owners,
                                                      CheckTotpChallengeService codes,
                                                      IssueLoginSessionUseCase sessions) {
        return new CompleteTotpLoginService(admission, owners, codes, sessions);
    }
}
