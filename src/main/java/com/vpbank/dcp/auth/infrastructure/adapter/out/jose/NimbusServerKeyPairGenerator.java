package com.vpbank.dcp.auth.infrastructure.adapter.out.jose;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.ServerKeyPairGenerator;
import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;

/** A fresh P-256 pair per trust transaction (Ksrv), as JWK text; the private part never leaves the restricted session. */
public final class NimbusServerKeyPairGenerator implements ServerKeyPairGenerator {
    @Override
    public ServerKeyPair next() {
        try {
            ECKey serverKeyPair = new ECKeyGenerator(Curve.P_256)
                    .keyIDFromThumbprint(true)
                    .generate();
            String publicJwk = serverKeyPair.toPublicJWK().toJSONString();
            String privateJwk = serverKeyPair.toJSONString();
            return new ServerKeyPair(publicJwk, privateJwk);
        } catch (JOSEException failure) {
            throw new IllegalStateException("P-256 key generation is not available", failure);
        }
    }
}
