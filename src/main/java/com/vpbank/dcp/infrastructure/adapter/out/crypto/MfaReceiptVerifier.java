package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.security.Digest32;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies the receipt the MFA service signs on {@code /check} (draft doc 20 §5.4). Only the
 * pinned MFA receipt key is accepted, and the claim set must match the status exactly.
 */
public final class MfaReceiptVerifier {
    static final String TYPE = "mfa-receipt+jwt";
    static final String AUDIENCE = "authentication-service";
    private static final Set<String> COMMON = Set.of("iss", "aud", "txn", "op", "purpose",
            "customerNumber", "contextDigest", "status", "iat", "exp", "jti");
    private static final Set<String> PASSED = union(COMMON, Set.of("factor", "verifiedAt"));
    private static final Set<String> STATUSES = Set.of("PASSED", "PENDING", "FAILED", "EXPIRED");
    private static final Duration MAXIMUM_LIFETIME = Duration.ofSeconds(60);
    private static final Duration SKEW = Duration.ofSeconds(5);

    private final String issuer;
    private final String kid;
    private final ECKey pinnedPublicKey;
    private final StrictJoseJson strictJson;
    private final Sha256Digests digests;

    public MfaReceiptVerifier(String issuer, String kid, ECKey pinnedPublicKey,
                              StrictJoseJson strictJson, Sha256Digests digests) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.kid = Objects.requireNonNull(kid, "kid");
        this.pinnedPublicKey = Objects.requireNonNull(pinnedPublicKey, "pinnedPublicKey");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.digests = Objects.requireNonNull(digests, "digests");
        if (issuer.isBlank() || kid.isBlank() || pinnedPublicKey.isPrivate()
                || !Curve.P_256.equals(pinnedPublicKey.getCurve())) {
            throw new InvalidCryptographicInputException();
        }
    }

    /** Throws {@link InvalidCryptographicInputException} for anything not exactly a receipt. */
    public VerifiedMfaReceipt verify(String compact, Instant now) {
        Objects.requireNonNull(compact, "compact");
        Objects.requireNonNull(now, "now");
        strictJson.checkCompactJws(compact);
        try {
            SignedJWT signed = SignedJWT.parse(compact);
            JWSHeader header = signed.getHeader();
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())
                    || header.getType() == null || !TYPE.equals(header.getType().toString())
                    || !kid.equals(header.getKeyID())
                    || header.getJWK() != null || header.getJWKURL() != null
                    || header.getX509CertURL() != null || header.getX509CertChain() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())
                    || !signed.verify(new ECDSAVerifier(pinnedPublicKey))) {
                throw new InvalidCryptographicInputException();
            }
            JWTClaimsSet claims = signed.getJWTClaimsSet();
            String status = claims.getStringClaim("status");
            if (status == null || !STATUSES.contains(status)
                    || !("PASSED".equals(status) ? PASSED : COMMON).equals(claims.getClaims().keySet())
                    || !issuer.equals(claims.getIssuer())
                    || claims.getAudience().size() != 1
                    || !AUDIENCE.equals(claims.getAudience().getFirst())
                    || claims.getIssueTime() == null || claims.getExpirationTime() == null
                    || claims.getJWTID() == null || claims.getJWTID().isBlank()) {
                throw new InvalidCryptographicInputException();
            }
            Instant issuedAt = claims.getIssueTime().toInstant();
            Instant expiresAt = claims.getExpirationTime().toInstant();
            if (now.isBefore(issuedAt.minus(SKEW)) || !now.isBefore(expiresAt)
                    || expiresAt.isAfter(issuedAt.plus(MAXIMUM_LIFETIME))
                    || ("PASSED".equals(status) && !"FACE".equals(claims.getStringClaim("factor")))) {
                throw new InvalidCryptographicInputException();
            }
            return new VerifiedMfaReceipt(status, claims.getStringClaim("txn"),
                    claims.getStringClaim("op"), claims.getStringClaim("purpose"),
                    claims.getStringClaim("customerNumber"), claims.getStringClaim("contextDigest"),
                    digests.sha256(compact.getBytes(StandardCharsets.US_ASCII)));
        } catch (ParseException | JOSEException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        var all = new java.util.HashSet<>(a);
        all.addAll(b);
        return Set.copyOf(all);
    }

    /** Signed claims; the caller compares every binding with its own trust state. */
    public record VerifiedMfaReceipt(String status, String transactionId, String authOperationId,
                                     String purpose, String customerNumber, String contextDigest,
                                     Digest32 receiptDigest) {
        @Override
        public String toString() {
            return "VerifiedMfaReceipt[redacted]";
        }
    }
}
