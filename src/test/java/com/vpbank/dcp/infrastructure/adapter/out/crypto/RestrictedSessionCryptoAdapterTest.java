package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.trusteddevice.LoginKeys;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class RestrictedSessionCryptoAdapterTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private final LookupKeyVersion version = new LookupKeyVersion("k1");
    private final TokenLookupHasher lookup = new TokenLookupHasher(version, new byte[32]);
    private final JsonMapper json = JsonMapper.builder().build();
    private final ECKey kenc;
    private final RestrictedSessionCryptoAdapter adapter;

    RestrictedSessionCryptoAdapterTest() throws Exception {
        kenc = new ECKeyGenerator(Curve.P_256).keyID("app-kenc").generate();
        ECKey receiptKey = new ECKeyGenerator(Curve.P_256).keyID("receipt-v1").generate();
        adapter = new RestrictedSessionCryptoAdapter(
                new BankingTokenIssuer(version, new SecureRandom()), lookup,
                new BankingTokenEnvelopeIssuer("https://auth.bank.test", receiptKey, json,
                        Clock.fixed(NOW, ZoneOffset.UTC)),
                version, new LengthPrefixedSigningInputEncoder(), new Sha256Digests());
    }

    /** The stored session is keyed by exactly the token the App can decrypt. */
    @Test
    void storedLookupMatchesTheDeliveredToken() throws Exception {
        PreparedRestrictedSession prepared = adapter.prepare(session(
                new SubjectId(UUID.randomUUID()), new TrustTarget.NewDevice()), NOW.plusSeconds(600));

        JWEObject envelope = JWEObject.parse(prepared.tokenEnvelope());
        envelope.decrypt(new ECDHDecrypter(kenc));
        JsonNode payload = json.readTree(envelope.getPayload().toString());
        String token = payload.path("accessToken").asText();

        assertThat(lookup.digest(token)).isEqualTo(prepared.lookup().digest());
        assertThat(payload.path("status").asText()).isEqualTo("NEED_TRUSTED_DEVICE");
        assertThat(prepared.expiresAt()).isEqualTo(NOW.plusSeconds(600));
    }

    /** The App must never be able to read a restricted receipt as an ACTIVE one. */
    @Test
    void receiptSaysNeedTrustedDeviceAndBindsTheKnownDeviceKey() throws Exception {
        Digest32 deviceKey = Digest32.fromBytes(new byte[] {
                7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
        PreparedRestrictedSession known = adapter.prepare(session(new SubjectId(UUID.randomUUID()),
                new TrustTarget.KnownDevice(new BindingId(UUID.randomUUID()), deviceKey, 2)), NOW.plusSeconds(600));
        PreparedRestrictedSession fresh = adapter.prepare(session(new SubjectId(UUID.randomUUID()),
                new TrustTarget.NewDevice()), NOW.plusSeconds(600));

        var knownClaims = SignedJWT.parse(known.receipt()).getJWTClaimsSet();
        assertThat(knownClaims.getStringClaim("status")).isEqualTo("NEED_TRUSTED_DEVICE");
        assertThat(knownClaims.getStringClaim("device_key_jkt")).isEqualTo(deviceKey.base64Url());
        var freshClaims = SignedJWT.parse(fresh.receipt()).getJWTClaimsSet();
        assertThat(freshClaims.getStringClaim("status")).isEqualTo("NEED_TRUSTED_DEVICE");
        assertThat(freshClaims.getClaim("device_key_jkt")).isNull();
    }

    /** The same device ID must not produce a value that links two customers. */
    @Test
    void deviceIdDigestIsBoundToTheOwner() {
        SubjectId first = new SubjectId(UUID.randomUUID());
        Digest32 a = digestFor(first);
        Digest32 again = digestFor(first);
        Digest32 other = digestFor(new SubjectId(UUID.randomUUID()));

        assertThat(again).isEqualTo(a);
        assertThat(other).isNotEqualTo(a);
    }

    private Digest32 digestFor(SubjectId owner) {
        return adapter.prepare(session(owner, new TrustTarget.NewDevice()), NOW.plusSeconds(600)).deviceIdDigest();
    }

    private RestrictedSession session(SubjectId owner, TrustTarget target) {
        return new RestrictedSession(UUID.randomUUID(), owner, new CustomerNumber("CUST-1"), 3,
                "neo-mobile", target, "device-id-1234567890",
                new LoginKeys("request-jwk", Digest32.fromBytes(new byte[32]),
                        kenc.toPublicJWK().toJSONString()),
                "ANDROID", UUID.randomUUID());
    }
}
