package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class PasswordOneShotVectorsTest {

    @Test
    void requestAndDeviceProofsBindTheSameOneShotOperationAndRecipient() throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot();
        JsonNode keys = ContractVectors.load().path("keys");
        SignedJWT request = SignedJWT.parse(vector.path("requestKeyProof").asText());
        SignedJWT device = SignedJWT.parse(vector.path("deviceProof").asText());

        assertThat(request.verify(new ECDSAVerifier(
                ECKey.parse(keys.path("Kreq").path("jwk").toString())))).isTrue();
        assertThat(device.verify(new ECDSAVerifier(
                ECKey.parse(keys.path("Kdev").path("jwk").toString())))).isTrue();
        assertThat(request.getHeader().getKeyID()).isEqualTo(vector.path("requestKeyJkt").asText());
        assertThat(device.getHeader().getKeyID()).isEqualTo(vector.path("deviceKeyJkt").asText());

        for (SignedJWT proof : List.of(request, device)) {
            var claims = proof.getJWTClaimsSet();
            assertThat(claims.getStringClaim("operationId")).isEqualTo(vector.path("operationId").asText());
            assertThat(claims.getStringClaim("installationHash"))
                    .isEqualTo(vector.path("installationHash").asText());
            assertThat(claims.getStringClaim("requestKeyJkt"))
                    .isEqualTo(vector.path("requestKeyJkt").asText());
            assertThat(claims.getStringClaim("responseKeyJkt"))
                    .isEqualTo(vector.path("responseKeyJkt").asText());
            assertThat(claims.getStringClaim("deviceBindingId"))
                    .isEqualTo("22222222-2222-4222-8222-222222222222");
            assertThat(claims.getStringClaim("username")).isEqualTo("alice");
        }
        assertThat(device.getJWTClaimsSet().getStringClaim("deviceKeyJkt"))
                .isEqualTo(vector.path("deviceKeyJkt").asText());
        assertThat(request.getJWTClaimsSet().getStringClaim("purpose"))
                .isEqualTo("PASSWORD_LOGIN_KEY_BINDING");
        assertThat(device.getJWTClaimsSet().getStringClaim("purpose"))
                .isEqualTo("PASSWORD_LOGIN_DEVICE_PROOF");
    }

    @Test
    void passwordCommandHmacIncludesTheSecretWithoutPersistingAPlainHash() throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot().path("commandHmac");
        byte[] testKey = HexFormat.of().parseHex(vector.path("testKeyHex").asText());
        List<String> fields = new ArrayList<>();
        vector.path("fields").forEach(field -> fields.add(field.asText()));

        assertThat(hmac(fields, testKey)).isEqualTo(vector.path("expectedBase64Url").asText());
        fields.set(6, "changed-fixture-password");
        assertThat(hmac(fields, testKey)).isNotEqualTo(vector.path("expectedBase64Url").asText());
        fields.set(6, "fixture-password-ONLY");
        fields.set(10, "different-recipient-key");
        assertThat(hmac(fields, testKey)).isNotEqualTo(vector.path("expectedBase64Url").asText());
    }

    private String hmac(List<String> fields, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] input = new ChallengeSigningInput().encode(fields);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(input));
        java.util.Arrays.fill(input, (byte) 0);
        return encoded;
    }
}
