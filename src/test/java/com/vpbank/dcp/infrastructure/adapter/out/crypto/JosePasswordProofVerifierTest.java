package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.vpbank.dcp.core.port.out.password.InvalidPasswordProofException;
import com.vpbank.dcp.core.port.out.security.DpopExpectation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordProofRequest;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class JosePasswordProofVerifierTest {

    private final StrictJoseJson json = new StrictJoseJson();
    private final Sha256Digests digests = new Sha256Digests();
    private final JosePasswordProofVerifier verifier = new JosePasswordProofVerifier(
            json, digests);

    @Test
    void verifiesKreqKdevAndKencAgainstTheSameOperation() throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot();
        SignedJWT requestProof = SignedJWT.parse(vector.path("requestKeyProof").asText());
        assertThat(requestProof.getJWTClaimsSet().getClaims().keySet())
                .containsExactlyInAnyOrder("v", "purpose", "operationId", "appId",
                        "platform", "installationHash", "username", "deviceBindingId",
                        "requestKeyJkt", "responseKeyJkt", "iat", "exp", "jti");
        assertThat(ECKey.parse(responseKey()).computeThumbprint().toString())
                .isEqualTo(vector.path("responseKeyJkt").asText());
        var proofs = verifier.verify(request(vector, "alice", responseKey()), storedDeviceKey());
        assertThat(proofs.requestKey().digest().base64Url())
                .isEqualTo(vector.path("requestKeyJkt").asText());
        assertThat(proofs.deviceKeyThumbprint().base64Url())
                .isEqualTo(vector.path("deviceKeyJkt").asText());
        assertThat(proofs.responseKeyThumbprint().base64Url())
                .isEqualTo(vector.path("responseKeyJkt").asText());
        assertThat(proofs.proofIds().deviceKey()).isNotNull();
    }

    @Test
    void rejectsChangedUsernameRecipientAndDeviceKey() throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot();
        assertThatThrownBy(() -> verifier.verify(request(vector, "bob", responseKey()),
                storedDeviceKey())).isInstanceOf(InvalidPasswordProofException.class);
        ECKey otherRecipient = ECKey.parse(ContractVectors.load()
                .path("keys").path("Kreq").path("jwk").toString());
        assertThatThrownBy(() -> verifier.verify(request(vector, "alice",
                otherRecipient.toJSONString()), storedDeviceKey()))
                .isInstanceOf(InvalidPasswordProofException.class);
        byte[] wrongKey = Base64.getUrlDecoder().decode(ContractVectors.load()
                .path("keys").path("Kreq").path("spki").asText());
        assertThatThrownBy(() -> verifier.verify(request(vector, "alice", responseKey()),
                new StoredDeviceKey(wrongKey,
                        Digest32.fromBase64Url(vector.path("deviceKeyJkt").asText()))))
                .isInstanceOf(InvalidPasswordProofException.class);
    }

    private PasswordProofRequest request(JsonNode vector, String username,
                                         String recipientJwk) throws Exception {
        var operation = new PasswordOperationContext(
                UUID.fromString(vector.path("operationId").asText()), "neo-mobile", "ANDROID",
                vector.path("installationId").asText(), username,
                UUID.fromString("22222222-2222-4222-8222-222222222222"));
        var wire = new PasswordWireProofs(
                new SpringDpopProofDecoder(digests, json).verify(dpop(),
                        DpopExpectation.forInitial("POST",
                                URI.create("https://api.bank.example/api/v1/authentications/password"),
                                Instant.ofEpochSecond(1791687601))), vector.path("requestKeyProof").asText(),
                vector.path("deviceProof").asText(), recipientJwk);
        return new PasswordProofRequest(operation, wire, Instant.ofEpochSecond(1791687601));
    }

    private String responseKey() throws Exception {
        return ECKey.parse(ContractVectors.loadSoftwareKeys()
                .path("recipientPrivateJwk").toString()).toPublicJWK().toJSONString();
    }

    private StoredDeviceKey storedDeviceKey() throws Exception {
        JsonNode key = ContractVectors.load().path("keys").path("Kdev");
        return new StoredDeviceKey(Base64.getUrlDecoder().decode(key.path("spki").asText()),
                Digest32.fromBase64Url(key.path("jkt").asText()));
    }

    private String dpop() throws Exception {
        JsonNode key = ContractVectors.load().path("keys").path("Kreq");
        ECKey privateKey = new ECKey.Builder(ECKey.parse(key.path("jwk").toString()))
                .d(Base64URL.encode(java.util.HexFormat.of().parseHex(
                        key.path("privateScalarHex").asText())))
                .build();
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(privateKey.toPublicJWK()).build();
        var claims = new JWTClaimsSet.Builder().jwtID("password-dpop-0001")
                .issueTime(Date.from(Instant.ofEpochSecond(1791687600)))
                .claim("htm", "POST")
                .claim("htu", "https://api.bank.example/api/v1/authentications/password")
                .build();
        SignedJWT proof = new SignedJWT(header, claims);
        proof.sign(new ECDSASigner(privateKey));
        return proof.serialize();
    }
}
