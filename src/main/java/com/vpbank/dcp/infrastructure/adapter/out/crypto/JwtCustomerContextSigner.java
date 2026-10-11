package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.port.out.session.CustomerContextSigner;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/** Audience- and action-scoped context; domains must verify this independent signer. */
public final class JwtCustomerContextSigner implements CustomerContextSigner {
    private final String issuer;
    private final ECKey signingKey;
    private final Clock clock;

    public JwtCustomerContextSigner(String issuer, ECKey signingKey, Clock clock) {
        this.issuer = Objects.requireNonNull(issuer);
        this.signingKey = Objects.requireNonNull(signingKey);
        this.clock = Objects.requireNonNull(clock);
        if (!issuer.startsWith("https://") || !signingKey.isPrivate()
                || !Curve.P_256.equals(signingKey.getCurve())
                || signingKey.getKeyID() == null) {
            throw new InvalidCryptographicInputException();
        }
    }

    @Override
    public String sign(UUID subjectId, UUID bindingId, String appId, String audience,
                       String action, Instant expiresAt) {
        Instant now = clock.instant();
        if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plusSeconds(30))) {
            throw new InvalidCryptographicInputException();
        }
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(issuer).subject(subjectId.toString()).audience(audience)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(now)).notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(expiresAt))
                    .claim("purpose", "BANKING_CUSTOMER_CONTEXT")
                    .claim("app_id", appId)
                    .claim("device_binding_id", bindingId.toString())
                    .claim("action", action).build();
            SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("bank-customer-context+jwt"))
                    .keyID(signingKey.getKeyID()).build(), claims);
            signed.sign(new ECDSASigner(signingKey));
            return signed.serialize();
        } catch (JOSEException failure) {
            throw new CryptographicProviderUnavailableException(failure);
        }
    }
}
