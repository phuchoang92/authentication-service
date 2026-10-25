package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.security.DpopExpectation;
import com.vpbank.dcp.core.security.DpopProofDecoder;
import com.vpbank.dcp.core.security.InvalidDpopProofException;
import com.vpbank.dcp.core.security.VerifiedDpopProof;
import java.text.ParseException;
import java.util.Objects;

/** Extracts unverified key/replay metadata only when the startup guard authorizes non-production. */
public final class NonProductionDpopProofDecoder implements DpopProofDecoder {
    private final Sha256Digests digests;
    private final StrictJoseJson json;
    private final DpopAlgorithmPolicy algorithms;

    public NonProductionDpopProofDecoder(Sha256Digests digests, StrictJoseJson json,
                                        DpopAlgorithmPolicy algorithms) {
        this.digests = Objects.requireNonNull(digests);
        this.json = Objects.requireNonNull(json);
        this.algorithms = Objects.requireNonNull(algorithms);
    }

    @Override
    public VerifiedDpopProof verify(String compact, DpopExpectation expectation) {
        Objects.requireNonNull(expectation);
        try {
            if (compact == null || compact.length() > 4096 || compact.split("\\.", -1).length != 3) {
                throw new InvalidCryptographicInputException();
            }
            json.checkCompactJws(compact);
            SignedJWT proof = SignedJWT.parse(compact);
            var header = proof.getHeader();
            if (header.getType() == null || !"dpop+jwt".equals(header.getType().toString())
                    || header.getJWKURL() != null || header.getX509CertURL() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())) {
                throw new InvalidCryptographicInputException();
            }
            JWK key = header.getJWK();
            algorithms.publicKey(key, header.getAlgorithm());
            var claims = proof.getJWTClaimsSet();
            if (claims.getJWTID() == null || claims.getJWTID().isBlank() || claims.getIssueTime() == null) {
                throw new InvalidCryptographicInputException();
            }
            return new VerifiedDpopProof(new RequestKeyThumbprint(
                    Digest32.fromBase64Url(key.computeThumbprint().toString())),
                    digests.ofProofId(claims.getJWTID()), claims.getIssueTime().toInstant(),
                    key.toPublicJWK().toJSONString(),
                    VerifiedDpopProof.Verification.DISABLED_FOR_NON_PRODUCTION);
        } catch (ParseException | JOSEException | IllegalArgumentException | NullPointerException failure) {
            throw new InvalidDpopProofException(failure);
        }
    }
}
