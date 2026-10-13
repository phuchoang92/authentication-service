package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.port.out.security.DpopExpectation;
import com.vpbank.dcp.core.port.out.security.InvalidDpopProofException;
import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SpringDpopProofDecoderTest {
    private static final Instant NOW = Instant.parse("2026-10-12T00:00:00Z");
    private static final URI URI = java.net.URI.create("https://api.bank.example/api/v1/authentications/password");
    private final SpringDpopProofDecoder decoder = new SpringDpopProofDecoder(new Sha256Digests(), new StrictJoseJson());
    private final DpopExpectation initial = DpopExpectation.forInitial("POST", URI, NOW);
    private final ECKey key;

    SpringDpopProofDecoderTest() throws Exception {
        key = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void libraryVerifiesSignatureAndReturnsTheVerifiedPublicKeyWithoutLocalReplayState() throws Exception {
        String proof = proof(claims -> {});
        var verified = decoder.verify(proof, initial);
        assertThat(verified.publicJwk()).isEqualTo(key.toPublicJWK().toJSONString());
        assertThat(verified.requestKey().digest().base64Url()).isEqualTo(key.computeThumbprint().toString());
        assertThat(decoder.verify(proof, initial)).isEqualTo(verified);
        assertThat(verified.toString()).doesNotContain(verified.publicJwk());
        var wrongSignature = new SignedJWT(header(), claims().build());
        wrongSignature.sign(new ECDSASigner(new ECKeyGenerator(Curve.P_256).generate()));
        rejects(wrongSignature.serialize());
    }

    @Test
    void enforcesThirtySecondAgeAndFiveSecondFutureSkew() throws Exception {
        decoder.verify(proof(claims -> claims.issueTime(Date.from(NOW.minusSeconds(30)))), initial);
        decoder.verify(proof(claims -> claims.issueTime(Date.from(NOW.plusSeconds(5)))), initial);
        rejects(proof(claims -> claims.issueTime(Date.from(NOW.minusSeconds(31)))));
        rejects(proof(claims -> claims.issueTime(Date.from(NOW.plusSeconds(6)))));
        rejects(proof(claims -> claims.issueTime(null)));
    }

    @Test
    void rejectsWrongMethodUriNonceTokenHashAndClaimTypes() throws Exception {
        rejects(proof(claims -> claims.claim("htm", "GET")));
        rejects(proof(claims -> claims.claim("htm", 123)));
        rejects(proof(claims -> claims.claim("htu", "https://attacker.example/api/v1/authentications/password")));
        rejects(proof(claims -> claims.claim("htu", URI + "?query=1")));
        rejects(proof(claims -> claims.claim("htu", "https://api.bank.example/api/../v1/authentications/password")));
        rejects(proof(claims -> claims.claim("nonce", "unexpected")));
        rejects(proof(claims -> claims.claim("ath", "unexpected")));
        rejects(proof(claims -> claims.jwtID(" ")));
        rejects(proof(claims -> claims.claim("exp", NOW.plusSeconds(60).getEpochSecond())));
    }

    @Test
    void keepsThePinnedEs256PublicKeyAndHeaderProfile() throws Exception {
        var wrongType = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("JWT")).jwk(key.toPublicJWK()).build(), claims().build());
        wrongType.sign(new ECDSASigner(key));
        rejects(wrongType.serialize());
        var parts = proof(claims -> {}).split("\\.");
        String privateHeader = "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":" + key.toJSONString() + "}";
        rejects(com.nimbusds.jose.util.Base64URL.encode(privateHeader) + "." + parts[1] + "." + parts[2]);
        var remoteKey = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK())
                .jwkURL(java.net.URI.create("https://attacker.example/jwks")).build(), claims().build());
        remoteKey.sign(new ECDSASigner(key));
        rejects(remoteKey.serialize());
        var otherCurve = new ECKeyGenerator(Curve.P_384).generate();
        var otherAlgorithm = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES384)
                .type(new JOSEObjectType("dpop+jwt")).jwk(otherCurve.toPublicJWK()).build(), claims().build());
        otherAlgorithm.sign(new ECDSASigner(otherCurve));
        rejects(otherAlgorithm.serialize());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
    void configuredAlgorithmsVerifyRealSignaturesAndRejectTampering(String name) throws Exception {
        JWSAlgorithm algorithm = JWSAlgorithm.parse(name);
        JWK signingKey = JWSAlgorithm.Family.EC.contains(algorithm)
                ? new ECKeyGenerator(Curve.forJWSAlgorithm(algorithm).iterator().next()).generate()
                : new RSAKeyGenerator(2048).generate();
        var proof = new SignedJWT(new JWSHeader.Builder(algorithm).type(new JOSEObjectType("dpop+jwt"))
                .jwk(signingKey.toPublicJWK()).build(), claims().build());
        proof.sign(signingKey instanceof ECKey ec ? new ECDSASigner(ec)
                : new RSASSASigner(signingKey.toRSAKey()));
        var configured = new SpringDpopProofDecoder(new Sha256Digests(), new StrictJoseJson(),
                new DpopAlgorithmPolicy(Set.of(name)));
        var verified = configured.verify(proof.serialize(), initial);
        assertThat(verified.publicJwk()).isEqualTo(signingKey.toPublicJWK().toJSONString());
        assertThat(verified.requestKey().digest().base64Url()).isEqualTo(signingKey.computeThumbprint().toString());
        assertThat(verified.verification()).isEqualTo(com.vpbank.dcp.core.port.out.security.VerifiedDpopProof.Verification.VERIFIED);
        String[] parts = proof.serialize().split("\\.");
        byte[] signature = java.util.Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 1;
        String tampered = parts[0] + "." + parts[1] + "."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        assertThatThrownBy(() -> configured.verify(tampered, initial)).isInstanceOf(InvalidDpopProofException.class);
        if (!"ES256".equals(name)) {
            rejects(proof.serialize());
        }
    }

    @Test
    void algorithmPolicyRejectsMismatchedCurvesKeyFamiliesAndWeakRsaKeys() throws Exception {
        var algorithms = new DpopAlgorithmPolicy(Set.of("ES256", "RS256"));
        var otherCurve = new ECKeyGenerator(Curve.P_384).generate().toPublicJWK();
        var generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        var weakRsa = new com.nimbusds.jose.jwk.RSAKey.Builder(
                (java.security.interfaces.RSAPublicKey) generator.generateKeyPair().getPublic()).build();
        assertThatThrownBy(() -> algorithms.publicKey(otherCurve, JWSAlgorithm.ES256))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThatThrownBy(() -> algorithms.publicKey(key.toPublicJWK(), JWSAlgorithm.RS256))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThatThrownBy(() -> algorithms.publicKey(weakRsa, JWSAlgorithm.RS256))
                .isInstanceOf(InvalidCryptographicInputException.class);
    }

    private void rejects(String compact) {
        assertThatThrownBy(() -> decoder.verify(compact, initial)).isInstanceOf(InvalidDpopProofException.class);
    }

    private String proof(Consumer<JWTClaimsSet.Builder> change) throws Exception {
        var claims = claims();
        change.accept(claims);
        var proof = new SignedJWT(header(), claims.build());
        proof.sign(new ECDSASigner(key));
        return proof.serialize();
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().jwtID("proof-test-only")
                .issueTime(Date.from(NOW)).claim("htm", "POST").claim("htu", URI.toString());
    }

    private JWSHeader header() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK()).build();
    }
}
