package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.security.DpopExpectation;
import com.vpbank.dcp.core.security.DpopProofDecoder;
import com.vpbank.dcp.core.security.InvalidDpopProofException;
import com.vpbank.dcp.core.security.VerifiedDpopProof;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuedAtValidator;

/**
 * Verifies JOSE and server-pinned HTTP bindings; replay reservation remains a separate atomic step.
 */
public final class SpringDpopProofDecoder implements DpopProofDecoder {

    private static final Set<String> ALLOWED_CLAIMS = Set.of(
            "jti", "htm", "htu", "iat", "nonce", "ath");

    private final Sha256Digests digests;
    private final StrictJoseJson strictJson;
    private final DpopAlgorithmPolicy algorithms;

    public SpringDpopProofDecoder(Sha256Digests digests, StrictJoseJson strictJson) {
        this(digests, strictJson, new DpopAlgorithmPolicy(Set.of("ES256")));
    }

    public SpringDpopProofDecoder(Sha256Digests digests, StrictJoseJson strictJson,
                                  DpopAlgorithmPolicy algorithms) {
        this.digests = Objects.requireNonNull(digests, "digests");
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.algorithms = Objects.requireNonNull(algorithms, "algorithms");
    }

    @Override
    public VerifiedDpopProof verify(String compact, DpopExpectation expectation) {
        Objects.requireNonNull(compact, "compact");
        Objects.requireNonNull(expectation, "expectation");
        try {
            if (compact.length() > 4096 || compact.split("\\.", -1).length != 3) {
                throw new InvalidCryptographicInputException();
            }
            strictJson.checkCompactJws(compact);
            JWK publicKey = checkedPublicKey(SignedJWT.parse(compact).getHeader());
            var context = DPoPProofContext.withDPoPProof(compact)
                    .method(expectation.method()).targetUri(canonicalExternalUri(expectation.externalUri()))
                    .build();
            var issuedAt = new JwtIssuedAtValidator(true);
            issuedAt.setClock(Clock.fixed(expectation.now(), ZoneOffset.UTC));
            issuedAt.setClockSkew(Duration.ofSeconds(30));
            var factory = new DPoPProofJwtDecoderFactory();
            // Use Spring's signature/type decoder and claim validators. Replay belongs to the
            // existing Redis reservation, never the factory's default per-instance replay cache.
            factory.setJwtValidatorFactory(ignored -> new DelegatingOAuth2TokenValidator<>(
                    new JwtClaimValidator<String>("htm", expectation.method()::equals),
                    new JwtClaimValidator<String>("htu", uri -> uri != null &&
                            canonicalExternalUri(expectation.externalUri())
                                    .equals(canonicalExternalUri(URI.create(uri)))),
                    issuedAt,
                    new JwtClaimValidator<Instant>("iat", time ->
                            !time.isAfter(expectation.now().plusSeconds(5))),
                    new JwtClaimValidator<String>("jti", id -> !id.isBlank())));
            Jwt proof = factory.createDecoder(context).decode(compact);
            RequestKeyThumbprint requestKey = new RequestKeyThumbprint(
                    Digest32.fromBase64Url(publicKey.computeThumbprint().toString()));
            if (!ALLOWED_CLAIMS.containsAll(proof.getClaims().keySet())
                    || (expectation.requestKey() != null && !expectation.requestKey().equals(requestKey))
                    || !Objects.equals(expectation.nonce(), proof.getClaim("nonce"))
                    || !Objects.equals(expectedTokenHash(expectation), proof.getClaim("ath"))) {
                throw new InvalidCryptographicInputException();
            }
            return new VerifiedDpopProof(requestKey, digests.ofProofId(proof.getId()),
                    proof.getIssuedAt(), publicKey.toPublicJWK().toJSONString());
        } catch (JOSEException | ParseException | JwtException | IllegalArgumentException
                 | NullPointerException | ClassCastException failure) {
            throw new InvalidDpopProofException(failure);
        }
    }

    private String expectedTokenHash(DpopExpectation expectation) {
        return expectation.exactToken() == null ? null : digests.ofToken(expectation.exactToken()).base64Url();
    }

    private JWK checkedPublicKey(JWSHeader header) throws JOSEException {
        if (header.getType() == null
                || !"dpop+jwt".equals(header.getType().toString())
                || header.getJWKURL() != null
                || header.getX509CertURL() != null
                || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())) {
            throw new InvalidCryptographicInputException();
        }
        algorithms.publicKey(header.getJWK(), header.getAlgorithm());
        return header.getJWK();
    }

    private String canonicalExternalUri(URI uri) {
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getRawPath() == null || !uri.getRawPath().startsWith("/")
                || uri.getRawPath().contains("%")
                || uri.getRawPath().length() > 2048
                || hasDotSegment(uri.getRawPath())) {
            throw new InvalidCryptographicInputException();
        }
        int port = uri.getPort() == 443 ? -1 : uri.getPort();
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (host.contains(":")) {
            host = "[" + host + "]";
        }
        return "https://" + host + (port < 0 ? "" : ":" + port) + uri.getRawPath();
    }

    private boolean hasDotSegment(String path) {
        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)) {
                return true;
            }
        }
        return false;
    }
}
