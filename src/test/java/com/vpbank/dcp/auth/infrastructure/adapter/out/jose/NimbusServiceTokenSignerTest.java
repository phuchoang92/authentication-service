package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.domain.model.ServiceTokenClaims;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Slice 12: the token is ES256 under the named key and says exactly what the claims say, nothing more. */
class NimbusServiceTokenSignerTest {
    private static final Instant T0 = Instant.parse("2026-11-03T10:00:00Z");
    private static final UUID TOKEN_ID = UUID.fromString("00000000-0000-4000-8000-000000000001");

    @Test
    void theTokenCarriesExactlyTheClaimsUnderTheNamedKey() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).keyID("svc-2026-1").generate();
        NimbusServiceTokenSigner signer = new NimbusServiceTokenSigner(signingKey);

        String compact = signer.sign(ServiceTokenClaims.builder()
                .issuer("authentication-service")
                .issuedTo(new ServiceId("onboarding-service"))
                .audience("mobile-bff")
                .scope(ServiceScope.ONBOARDING)
                .businessReference(new BusinessReference("onb-1"))
                .issuedAt(T0)
                .expiresAt(T0.plus(Duration.ofMinutes(15)))
                .tokenId(TOKEN_ID)
                .build());

        SignedJWT token = SignedJWT.parse(compact);
        assertThat(token.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(token.getHeader().getType().getType()).isEqualTo("service-token+jwt");
        assertThat(token.getHeader().getKeyID()).isEqualTo("svc-2026-1");
        assertThat(token.getHeader().getJWK()).isNull();
        assertThat(token.verify(new ECDSAVerifier(signingKey.toPublicJWK()))).isTrue();

        JWTClaimsSet claims = token.getJWTClaimsSet();
        assertThat(claims.getClaims().keySet())
                .isEqualTo(Set.of("iss", "sub", "aud", "scope", "businessReference", "iat", "exp", "jti"));
        assertThat(claims.getIssuer()).isEqualTo("authentication-service");
        assertThat(claims.getSubject()).isEqualTo("onboarding-service");
        assertThat(claims.getAudience()).isEqualTo(List.of("mobile-bff"));
        assertThat(claims.getStringClaim("scope")).isEqualTo("onboarding");
        assertThat(claims.getStringClaim("businessReference")).isEqualTo("onb-1");
        assertThat(claims.getIssueTime()).isEqualTo(Date.from(T0));
        assertThat(claims.getExpirationTime()).isEqualTo(Date.from(T0.plus(Duration.ofMinutes(15))));
        assertThat(claims.getJWTID()).isEqualTo(TOKEN_ID.toString());

        ECKey otherKey = new ECKeyGenerator(Curve.P_256).keyID("svc-2026-1").generate();
        assertThat(token.verify(new ECDSAVerifier(otherKey.toPublicJWK()))).isFalse();
    }

    @Test
    void theSigningKeyMustBeAPrivateP256KeyWithAKeyId() throws Exception {
        ECKey named = new ECKeyGenerator(Curve.P_256).keyID("svc-2026-1").generate();
        assertThatThrownBy(() -> new NimbusServiceTokenSigner(named.toPublicJWK())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new NimbusServiceTokenSigner(new ECKeyGenerator(Curve.P_256).generate()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new NimbusServiceTokenSigner(new ECKeyGenerator(Curve.P_384).keyID("k").generate()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
