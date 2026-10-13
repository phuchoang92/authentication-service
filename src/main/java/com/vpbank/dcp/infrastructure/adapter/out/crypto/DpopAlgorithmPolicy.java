package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Set;

/** Server-selected asymmetric algorithms and matching public-key parameters. */
public final class DpopAlgorithmPolicy {
    private static final Map<JWSAlgorithm, Curve> EC_CURVES = Map.of(
            JWSAlgorithm.ES256, Curve.P_256,
            JWSAlgorithm.ES384, Curve.P_384,
            JWSAlgorithm.ES512, Curve.P_521);
    private static final Set<String> SUPPORTED = Set.of(
            "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512");
    private final Set<String> allowed;

    public DpopAlgorithmPolicy(Set<String> allowed) {
        if (allowed == null || allowed.isEmpty() || !SUPPORTED.containsAll(allowed)) {
            throw new InvalidDpopConfigurationException();
        }
        this.allowed = Set.copyOf(allowed);
    }

    public PublicKey publicKey(JWK key, JWSAlgorithm algorithm) throws JOSEException {
        if (algorithm == null || !allowed.contains(algorithm.getName()) || key == null || key.isPrivate()
                || (key.getAlgorithm() != null && !algorithm.equals(key.getAlgorithm()))) {
            throw new InvalidCryptographicInputException();
        }
        if (key instanceof ECKey ec && EC_CURVES.containsKey(algorithm)
                && EC_CURVES.get(algorithm).equals(ec.getCurve())) {
            return ec.toECPublicKey();
        }
        if (key instanceof RSAKey rsa && JWSAlgorithm.Family.RSA.contains(algorithm)
                && rsa.toRSAPublicKey().getModulus().bitLength() >= 2048) {
            return rsa.toRSAPublicKey();
        }
        throw new InvalidCryptographicInputException();
    }

    public void checkPublicKey(JWK key) throws JOSEException {
        for (String name : allowed) {
            try {
                publicKey(key, JWSAlgorithm.parse(name));
                return;
            } catch (InvalidCryptographicInputException ignored) {
                // Try the next server-allowed algorithm for this key.
            }
        }
        throw new InvalidCryptographicInputException();
    }
}
