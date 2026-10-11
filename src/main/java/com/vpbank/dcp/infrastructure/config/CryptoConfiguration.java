package com.vpbank.dcp.infrastructure.config;

import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ChallengeSigningInput;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BankingTokenEnvelopeIssuer;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.DpopProofVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.EnrollmentProofVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.JcsCommandDigest;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.JweEnvelopeInspector;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.ProofDigests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.SignedContextVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.config.properties.KeycloakContextTrustProperties;
import com.vpbank.dcp.infrastructure.config.properties.BankingTokenDeliveryProperties;
import java.text.ParseException;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@EnableConfigurationProperties({KeycloakContextTrustProperties.class,
        BankingTokenDeliveryProperties.class})
public class CryptoConfiguration {

    @Bean
    ProofDigests proofDigests() {
        return new ProofDigests();
    }

    @Bean
    StrictJoseJson strictJoseJson() {
        return new StrictJoseJson();
    }

    @Bean
    DpopProofVerifier dpopProofVerifier(ProofDigests digests, StrictJoseJson json) {
        return new DpopProofVerifier(digests, json);
    }

    @Bean
    JweEnvelopeInspector jweEnvelopeInspector(ProofDigests digests, StrictJoseJson json) {
        return new JweEnvelopeInspector(digests, json);
    }

    @Bean
    EnrollmentProofVerifier enrollmentProofVerifier(StrictJoseJson json, ProofDigests digests) {
        return new EnrollmentProofVerifier(json, digests);
    }

    @Bean
    JcsCommandDigest jcsCommandDigest(StrictJoseJson json, ProofDigests digests) {
        return new JcsCommandDigest(json, digests);
    }

    @Bean
    ChallengeSigningInput challengeSigningInput() {
        return new ChallengeSigningInput();
    }

    @Bean
    BankingTokenEnvelopeIssuer bankingTokenEnvelopeIssuer(BankingTokenDeliveryProperties properties,
                                                           JsonMapper json) {
        try {
            return new BankingTokenEnvelopeIssuer(properties.issuer(),
                    ECKey.parse(properties.receiptPrivateJwk()), json, Clock.systemUTC());
        } catch (ParseException | IllegalArgumentException failure) {
            throw new InvalidContextTrustConfigurationException(failure);
        }
    }

    @Bean
    SignedContextVerifier signedContextVerifier(KeycloakContextTrustProperties trust,
                                               StrictJoseJson json) {
        try {
            json.checkJson(trust.publicJwk());
            return new SignedContextVerifier(trust.issuer(), trust.keyId(),
                    ECKey.parse(trust.publicJwk()), json);
        } catch (ParseException | IllegalArgumentException failure) {
            throw new InvalidContextTrustConfigurationException(failure);
        }
    }

}
