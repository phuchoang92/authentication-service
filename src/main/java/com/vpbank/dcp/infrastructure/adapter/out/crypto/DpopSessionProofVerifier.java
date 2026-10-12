package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.port.out.session.BankingSessionLookup;
import com.vpbank.dcp.core.port.out.session.SessionProofVerifier;
import com.vpbank.dcp.core.port.out.session.VerifiedSessionProof;
import com.vpbank.dcp.core.port.out.session.InvalidSessionProofException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/** DPoP signature/ath/JKT is checked before Redis compares the nonce digest. */
public final class DpopSessionProofVerifier implements SessionProofVerifier {
    private final DpopProofVerifier dpop;
    private final Sha256Digests digests;

    public DpopSessionProofVerifier(DpopProofVerifier dpop, Sha256Digests digests) {
        this.dpop = Objects.requireNonNull(dpop);
        this.digests = Objects.requireNonNull(digests);
    }

    @Override
    public VerifiedSessionProof verify(String exactToken, String compactProof, String method,
                                       URI externalUri, BankingSessionLookup lookup, Instant now) {
        try {
            if (compactProof == null || compactProof.length() > 8192) {
                throw new InvalidCryptographicInputException();
            }
            String nonce = SignedJWT.parse(compactProof).getJWTClaimsSet().getStringClaim("nonce");
            if (nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}")
                    || Base64.getUrlDecoder().decode(nonce).length != 32) {
                throw new InvalidCryptographicInputException();
            }
            var verified = dpop.verify(compactProof, DpopExpectation.forToken(method,
                    externalUri, lookup.requestKey(), nonce, exactToken, now));
            return new VerifiedSessionProof(verified.proofIdDigest(),
                    digests.sha256(nonce.getBytes(StandardCharsets.US_ASCII)), nonce);
        } catch (ParseException | IllegalArgumentException failure) {
            throw new InvalidSessionProofException(failure);
        }
    }
}
