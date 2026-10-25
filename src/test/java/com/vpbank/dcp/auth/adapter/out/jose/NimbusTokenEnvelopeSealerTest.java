package com.vpbank.dcp.auth.adapter.out.jose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.auth.application.port.out.InvalidEncryptionKeyException;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class NimbusTokenEnvelopeSealerTest {
    private static final OpaqueToken TOKEN = new OpaqueToken("k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private final NimbusTokenEnvelopeSealer sealer = new NimbusTokenEnvelopeSealer();
    private final Session session = Session.start(SessionId.random(), new CustomerId("90359"), null, Channel.MOBILE,
            Instant.parse("2026-10-25T10:00:00Z"), new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20),
                    Duration.ofSeconds(30)));

    @Test
    void onlyTheHolderOfThePrivateKencCanReadTheToken() throws Exception {
        ECKey kenc = new ECKeyGenerator(Curve.P_256).generate();

        String compact = sealer.seal(kenc.toPublicJWK().toJSONString(), TOKEN, session);

        assertThat(compact).doesNotContain(TOKEN.value().substring(3));
        JWEObject jwe = JWEObject.parse(compact);
        assertThat(jwe.getHeader().getAlgorithm().getName()).isEqualTo("ECDH-ES");
        assertThat(jwe.getHeader().getEncryptionMethod().getName()).isEqualTo("A256GCM");
        assertThat(jwe.getHeader().getType().getType()).isEqualTo("BANKING_TOKEN");
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(kenc.computeThumbprint().toString());
        assertThat(jwe.getHeader().getCustomParam("ver")).isEqualTo(1L);
        jwe.decrypt(new ECDHDecrypter(kenc));
        assertThat(jwe.getPayload().toString()).contains("\"token\":\"" + TOKEN.value() + "\"")
                .contains("\"status\":\"ACTIVE\"").contains("\"customerId\":\"90359\"")
                .contains("\"idleExpiresAt\":\"2026-10-25T10:15:00Z\"");

        ECKey other = new ECKeyGenerator(Curve.P_256).generate();
        JWEObject again = JWEObject.parse(compact);
        assertThatThrownBy(() -> again.decrypt(new ECDHDecrypter(other))).isInstanceOf(Exception.class);
    }

    @Test
    void refusesKeysThatAreNotPublicP256() throws Exception {
        ECKey p384 = new ECKeyGenerator(Curve.P_384).generate();
        ECKey withPrivate = new ECKeyGenerator(Curve.P_256).generate();
        assertThatThrownBy(() -> sealer.seal("not json", TOKEN, session)).isInstanceOf(InvalidEncryptionKeyException.class);
        assertThatThrownBy(() -> sealer.seal(p384.toPublicJWK().toJSONString(), TOKEN, session))
                .isInstanceOf(InvalidEncryptionKeyException.class);
        assertThatThrownBy(() -> sealer.seal(withPrivate.toJSONString(), TOKEN, session))
                .isInstanceOf(InvalidEncryptionKeyException.class).hasMessageContaining("public");
        assertThatThrownBy(() -> sealer.seal("{\"kty\":\"oct\",\"k\":\"AAAA\"}", TOKEN, session))
                .isInstanceOf(InvalidEncryptionKeyException.class);
    }
}
