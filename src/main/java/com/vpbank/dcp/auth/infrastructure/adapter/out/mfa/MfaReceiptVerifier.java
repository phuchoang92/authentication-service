package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * DD 20 §5.4: the receipt is a compact ES256 JWS from a pinned MFA key (no jku/x5u), with an exact
 * claim set; any extra, missing or mismatched claim is REJECTED, never PENDING.
 */
@RequiredArgsConstructor
public final class MfaReceiptVerifier {
    static final String AUDIENCE = "authentication-service";
    static final Set<String> CLAIMS_BASE = Set.of("iss", "aud", "txn", "op", "purpose", "customerNumber", "contextDigest",
            "status", "iat", "exp", "jti");
    static final Set<String> CLAIMS_PASSED = Set.of("factor", "verifiedAt");
    static final Duration MAX_SKEW = Duration.ofSeconds(5);
    private static final String PURPOSE_TRUST_DEVICE = "TRUST_DEVICE";
    private static final String FACTOR_FACE = "FACE";
    private static final String STATUS_PASSED = "PASSED";
    private static final String STATUS_PENDING = "PENDING";
    private static final String STATUS_FAILED = "FAILED";
    private static final String STATUS_EXPIRED = "EXPIRED";

    @NonNull private final ECKey mfaReceiptKey;
    @NonNull private final String issuer;
    @NonNull private final Clock clock;

    public CheckResult verify(String receipt, String mfaTransactionId, EnrollmentId authOperationId,
                              CustomerId customerId, String contextDigest) {
        try {
            SignedJWT receiptJws = SignedJWT.parse(receipt);

            if (!signedByPinnedKey(receiptJws)) {
                return new CheckResult.Rejected();
            }

            JWTClaimsSet claims = receiptJws.getJWTClaimsSet();
            String status = claims.getStringClaim("status");

            boolean boundToThisCheck = hasExactClaimSet(claims, status)
                    && boundToTransaction(claims, mfaTransactionId, authOperationId, customerId, contextDigest)
                    && withinValidity(claims);
            if (!boundToThisCheck) {
                return new CheckResult.Rejected();
            }

            return switch (status) {
                case STATUS_PASSED -> passedWithFace(claims, receipt);
                case STATUS_PENDING -> new CheckResult.Pending();
                case STATUS_FAILED -> new CheckResult.Failed();
                case STATUS_EXPIRED -> new CheckResult.Expired();
                default -> new CheckResult.Rejected();
            };
        } catch (ParseException | JOSEException | ClassCastException invalid) {
            return new CheckResult.Rejected();
        }
    }

    /** ES256 under the pinned key; a {@code kid}, when present, must name that key. */
    private boolean signedByPinnedKey(SignedJWT receiptJws) throws JOSEException {
        JWSHeader header = receiptJws.getHeader();
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            return false;
        }
        boolean namesAnotherKey = header.getKeyID() != null && !header.getKeyID().equals(mfaReceiptKey.getKeyID());
        if (namesAnotherKey) {
            return false;
        }
        return receiptJws.verify(new ECDSAVerifier(mfaReceiptKey.toECPublicKey()));
    }

    /** PASSED receipts carry the factor claims as well; every other status carries the base set only. */
    private static boolean hasExactClaimSet(JWTClaimsSet claims, String status) {
        Set<String> expectedClaims = new HashSet<>(CLAIMS_BASE);
        if (STATUS_PASSED.equals(status)) {
            expectedClaims.addAll(CLAIMS_PASSED);
        }
        return expectedClaims.equals(claims.getClaims().keySet());
    }

    private boolean boundToTransaction(JWTClaimsSet claims, String mfaTransactionId, EnrollmentId authOperationId,
                                       CustomerId customerId, String contextDigest) throws ParseException {
        return issuer.equals(claims.getIssuer())
                && List.of(AUDIENCE).equals(claims.getAudience())
                && mfaTransactionId.equals(claims.getStringClaim("txn"))
                && authOperationId.value().toString().equals(claims.getStringClaim("op"))
                && PURPOSE_TRUST_DEVICE.equals(claims.getStringClaim("purpose"))
                && customerId.value().equals(claims.getStringClaim("customerNumber"))
                && contextDigest.equals(claims.getStringClaim("contextDigest"))
                && claims.getJWTID() != null
                && !claims.getJWTID().isBlank();
    }

    private boolean withinValidity(JWTClaimsSet claims) {
        if (claims.getExpirationTime() == null || claims.getIssueTime() == null) {
            return false;
        }
        Instant now = clock.instant();
        boolean notExpired = claims.getExpirationTime().toInstant().plus(MAX_SKEW).isAfter(now);
        boolean alreadyIssued = claims.getIssueTime().toInstant().minus(MAX_SKEW).isBefore(now);
        return notExpired && alreadyIssued;
    }

    /** Only a FACE factor passes this flow; the digest of the exact receipt text goes to the audit trail. */
    private static CheckResult passedWithFace(JWTClaimsSet claims, String receipt) throws ParseException {
        if (!FACTOR_FACE.equals(claims.getStringClaim("factor"))) {
            return new CheckResult.Rejected();
        }
        return new CheckResult.Passed(sha256(receipt));
    }

    static String sha256(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is not available", failure);
        }
    }
}
