package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.vpbank.dcp.core.password.InvalidPasswordProofException;
import com.vpbank.dcp.core.security.DpopExpectation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.password.PasswordOperationContext;
import com.vpbank.dcp.core.password.PasswordProofRequest;
import com.vpbank.dcp.core.password.PasswordWireProofs;
import com.vpbank.dcp.core.device.StoredDeviceKey;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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

    /**
     * A device trusted through the X-Wing key exchange stores a key that cannot sign, so its
     * ES256 device proof cannot be checked. Until that login path is decided it is refused.
     */
    @Test
    void deviceTrustedWithAnXWingKeyIsRefused() throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot();
        byte[] xWing = com.vpbank.dcp.hpke.XWingKeyPair.generate()
                .publicKey().toBytes();

        assertThatThrownBy(() -> verifier.verify(request(vector, "alice", responseKey()),
                new StoredDeviceKey(xWing, digests.sha256(xWing))))
                .isInstanceOf(InvalidPasswordProofException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
    void configuredRequestKeyAlgorithmsStillVerifyKreqKdevAndKencBindings(String name) throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot();
        JWSAlgorithm algorithm = JWSAlgorithm.parse(name);
        JWK key = JWSAlgorithm.Family.EC.contains(algorithm)
                ? new ECKeyGenerator(Curve.forJWSAlgorithm(algorithm).iterator().next()).generate()
                : new RSAKeyGenerator(2048).generate();
        JWSSigner signer = key instanceof ECKey ec ? new ECDSASigner(ec) : new RSASSASigner(key.toRSAKey());
        String requestJkt = key.computeThumbprint().toString();
        var algorithms = new DpopAlgorithmPolicy(Set.of(name));
        var original = request(vector, "alice", responseKey());

        var dpop = new SignedJWT(new JWSHeader.Builder(algorithm).type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK()).build(), SignedJWT.parse(dpop()).getJWTClaimsSet());
        dpop.sign(signer);
        var decoded = new SpringDpopProofDecoder(digests, json, algorithms).verify(dpop.serialize(),
                DpopExpectation.forInitial("POST", URI.create("https://api.bank.example/api/v1/authentications/password"),
                        original.now()));
        var requestProof = SignedJWT.parse(vector.path("requestKeyProof").asText());
        var changedRequestProof = new SignedJWT(new JWSHeader.Builder(algorithm)
                .type(requestProof.getHeader().getType()).keyID(requestJkt).build(),
                new JWTClaimsSet.Builder(requestProof.getJWTClaimsSet()).claim("requestKeyJkt", requestJkt).build());
        changedRequestProof.sign(signer);
        var deviceProof = SignedJWT.parse(vector.path("deviceProof").asText());
        var changedDeviceProof = new SignedJWT(deviceProof.getHeader(),
                new JWTClaimsSet.Builder(deviceProof.getJWTClaimsSet()).claim("requestKeyJkt", requestJkt).build());
        JsonNode device = ContractVectors.load().path("keys").path("Kdev");
        ECKey devicePrivateKey = new ECKey.Builder(ECKey.parse(device.path("jwk").toString()))
                .d(Base64URL.encode(java.util.HexFormat.of().parseHex(device.path("privateScalarHex").asText()))).build();
        changedDeviceProof.sign(new ECDSASigner(devicePrivateKey));
        var wire = new PasswordWireProofs(decoded, changedRequestProof.serialize(), changedDeviceProof.serialize(), responseKey());
        var configured = new JosePasswordProofVerifier(json, digests, algorithms);
        var verified = configured.verify(new PasswordProofRequest(original.operation(), wire, original.now()), storedDeviceKey());
        assertThat(verified.requestKey().digest().base64Url()).isEqualTo(requestJkt);
        assertThat(verified.deviceKeyThumbprint().base64Url()).isEqualTo(vector.path("deviceKeyJkt").asText());
        assertThat(verified.responseKeyThumbprint().base64Url()).isEqualTo(vector.path("responseKeyJkt").asText());

        var badProof = new SignedJWT(changedRequestProof.getHeader(),
                new JWTClaimsSet.Builder(changedRequestProof.getJWTClaimsSet()).claim("username", "bob").build());
        badProof.sign(signer);
        var changedWire = new PasswordWireProofs(decoded, badProof.serialize(), changedDeviceProof.serialize(), responseKey());
        assertThatThrownBy(() -> configured.verify(new PasswordProofRequest(original.operation(), changedWire, original.now()),
                storedDeviceKey())).isInstanceOf(InvalidPasswordProofException.class);
    }

    @Test
    void disablingDpopDoesNotDisableRequestKeySignatureOrCommandBinding() throws Exception {
        var vector = ContractVectors.loadPasswordOneShot();
        var original = request(vector, "alice", responseKey());
        var unverified = new NonProductionDpopProofDecoder(digests, json, new DpopAlgorithmPolicy(Set.of("ES256")))
                .verify(tamperSignature(dpop()), DpopExpectation.forInitial("GET", URI.create("https://other.example/wrong"),
                        original.now().plusSeconds(600)));
        var wire = new PasswordWireProofs(unverified, original.wire().requestKeyProof(), original.wire().deviceProof(), responseKey());
        assertThat(verifier.verify(new PasswordProofRequest(original.operation(), wire, original.now()), storedDeviceKey())
                .requestKey()).isEqualTo(unverified.requestKey());
        var invalidWire = new PasswordWireProofs(unverified, tamperSignature(wire.requestKeyProof()), wire.deviceProof(), responseKey());
        assertThatThrownBy(() -> verifier.verify(new PasswordProofRequest(original.operation(), invalidWire, original.now()),
                storedDeviceKey())).isInstanceOf(InvalidPasswordProofException.class);
    }

    private String tamperSignature(String compact) {
        String[] parts = compact.split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 1;
        return parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }

    private PasswordProofRequest request(JsonNode vector, String username,
                                         String recipientJwk) throws Exception {
        var operation = new PasswordOperationContext(
                UUID.fromString(vector.path("operationId").asText()), "neo-mobile", "ANDROID",
                vector.path("installationId").asText(), username,
                "22222222-2222-4222-8222-222222222222");
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
