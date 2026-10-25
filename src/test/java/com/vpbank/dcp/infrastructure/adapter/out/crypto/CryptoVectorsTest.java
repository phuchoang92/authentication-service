package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.security.DpopExpectation;
import com.vpbank.dcp.core.security.VerifiedDpopProof;
import com.vpbank.dcp.core.security.InvalidDpopProofException;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.JWEObject;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class CryptoVectorsTest {

    private final StrictJoseJson strictJson = new StrictJoseJson();
    private final Sha256Digests digests = new Sha256Digests();

    @Test
    void dpopProofBindsMethodUriTokenNonceAndKreq() throws Exception {
        JsonNode vectors = ContractVectors.load();
        String token = vectors.path("dpop").path("token").asText();
        String jkt = vectors.path("keys").path("Kreq").path("jkt").asText();
        SpringDpopProofDecoder verifier = new SpringDpopProofDecoder(digests, strictJson);
        var expected = DpopExpectation.forToken("GET", URI.create("https://api.bank.example/api/accounts"),
                new RequestKeyThumbprint(Digest32.fromBase64Url(jkt)),
                vectors.path("dpop").path("protectedPayload").path("nonce").asText(),
                token, Instant.ofEpochSecond(vectors.path("clock").asLong()));

        VerifiedDpopProof proof = verifier.verify(vectors.path("dpop").path("protected").asText(), expected);
        assertThat(proof.requestKey()).isEqualTo(expected.requestKey());
        assertThat(proof.proofIdDigest().base64Url())
                .isEqualTo(vectors.path("authorityKeys").path("jtiDigest").asText());

        assertThatThrownBy(() -> verifier.verify(vectors.path("dpop").path("protected").asText(),
                DpopExpectation.forToken("POST", expected.externalUri(), expected.requestKey(),
                        expected.nonce(), token, expected.now())))
                .isInstanceOf(InvalidDpopProofException.class);
        assertThatThrownBy(() -> verifier.verify(vectors.path("dpop").path("protected").asText(),
                DpopExpectation.forToken("GET", expected.externalUri(), expected.requestKey(),
                        expected.nonce(), "stolen-token", expected.now())))
                .isInstanceOf(InvalidDpopProofException.class);
    }

    @Test
    void contextUsesPinnedKeyAndExpires() throws Exception {
        JsonNode vectors = ContractVectors.load();
        ECKey publicKey = ECKey.parse(vectors.path("contextSigner").path("jwk").toString());
        String compact = vectors.path("contexts").path("password").path("compact").asText();
        SignedContextVerifier verifier = new SignedContextVerifier(
                vectors.path("contexts").path("password").path("claims").path("iss").asText(),
                "test-kc-context-signing", publicKey, strictJson);

        assertThat(verifier.verify(compact, "neo-mobile", "PASSWORD_LOGIN",
                Instant.ofEpochSecond(vectors.path("clock").asLong())).getJWTID())
                .isEqualTo("KCCTX-test-vector-0001");
        assertThatThrownBy(() -> verifier.verify(compact, "other-client", "PASSWORD_LOGIN",
                Instant.ofEpochSecond(vectors.path("clock").asLong())))
                .isInstanceOf(InvalidCryptographicInputException.class);
        assertThatThrownBy(() -> verifier.verify(compact, "neo-mobile", "PASSWORD_LOGIN",
                Instant.ofEpochSecond(vectors.path("clock").asLong() + 121)))
                .isInstanceOf(InvalidCryptographicInputException.class);
    }

    @Test
    void jweHeadersAreStrictAndRecipientCanDecryptSharedVector() throws Exception {
        JsonNode vectors = ContractVectors.load();
        String compact = vectors.path("jwe").path("password").path("compact").asText();
        var envelope = new JweEnvelopeInspector(digests, strictJson)
                .inspect(compact, "test-password-recipient");
        assertThat(envelope.recipientKid()).isEqualTo("test-password-recipient");
        assertThatThrownBy(() -> new JweEnvelopeInspector(digests, strictJson)
                .inspect(compact, "test-otp-recipient"))
                .isInstanceOf(InvalidCryptographicInputException.class);

        String pem = vectors.path("recipients").path("password").path("privatePem").asText();
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[^-]+-----", ""));
        var recipient = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        JWEObject object = JWEObject.parse(compact);
        object.decrypt(new RSADecrypter(recipient));
        assertThat(new tools.jackson.databind.json.JsonMapper().readTree(object.getPayload().toString()))
                .isEqualTo(vectors.path("jwe").path("password").path("plaintext"));
    }

    @Test
    void signingInputAndJcsDigestMatchSharedVectors() throws Exception {
        JsonNode vectors = ContractVectors.load();
        var input = vectors.path("inputs").path("deviceLogin");
        List<String> fields = new java.util.ArrayList<>();
        input.path("fields").forEach(value -> fields.add(value.asText()));
        byte[] encoded = new LengthPrefixedSigningInputEncoder().encode(fields);
        assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(encoded))
                .isEqualTo(input.path("bytes").asText());
        assertThat(digests.sha256(encoded).base64Url()).isEqualTo(input.path("sha256").asText());

        String command = vectors.path("enrollment").path("command").toString();
        assertThat(new JcsCommandDigest(strictJson, digests).ofCommand(command).base64Url())
                .isEqualTo(vectors.path("enrollment").path("payload").path("commandDigest").asText());
    }

    @Test
    void enrollmentProofBindsTheExactCommandAndNewKey() throws Exception {
        JsonNode vectors = ContractVectors.load();
        JsonNode payload = vectors.path("enrollment").path("payload");
        ECKey requestKey = ECKey.parse(vectors.path("keys").path("Kreq").path("jwk").toString());
        ExpectedEnrollmentProof expected = new ExpectedEnrollmentProof(
                UUID.fromString(payload.path("enrollmentId").asText()),
                payload.path("purpose").asText(), payload.path("appId").asText(),
                new RequestKeyThumbprint(Digest32.fromBase64Url(payload.path("requestKeyJkt").asText())),
                Digest32.fromBase64Url(payload.path("ath").asText()),
                Digest32.fromBase64Url(payload.path("inputDigest").asText()),
                Digest32.fromBase64Url(payload.path("newKeyJkt").asText()),
                Digest32.fromBase64Url(payload.path("commandDigest").asText()),
                Instant.ofEpochSecond(vectors.path("clock").asLong()));
        EnrollmentProofVerifier verifier = new EnrollmentProofVerifier(strictJson, digests);
        String compact = vectors.path("enrollment").path("proof").asText();

        assertThat(verifier.verify(compact, requestKey, expected).proofIdDigest())
                .isEqualTo(digests.ofProofId(payload.path("jti").asText()));
        ExpectedEnrollmentProof substitutedCommand = new ExpectedEnrollmentProof(
                expected.enrollmentId(), expected.purpose(), expected.appId(), expected.requestKey(),
                expected.tokenHash(), expected.signingInputHash(), expected.newKeyThumbprint(),
                digests.sha256("changed-command".getBytes(StandardCharsets.UTF_8)), expected.now());
        assertThatThrownBy(() -> verifier.verify(compact, requestKey, substitutedCommand))
                .isInstanceOf(InvalidCryptographicInputException.class);
    }
}
