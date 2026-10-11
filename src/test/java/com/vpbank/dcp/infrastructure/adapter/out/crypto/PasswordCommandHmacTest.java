package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordSemanticCommand;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.testsupport.ContractVectors;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class PasswordCommandHmacTest {

    @Test
    void matchesSharedVectorAndDetectsChangedPasswordOrRecipient() throws Exception {
        JsonNode vector = ContractVectors.loadPasswordOneShot();
        JsonNode hmac = vector.path("commandHmac");
        var hasher = new PasswordCommandHmac("h1", Map.of("h1",
                HexFormat.of().parseHex(hmac.path("testKeyHex").asText())),
                new ChallengeSigningInput());

        assertThat(hasher.digest(command(vector, "fixture-password-ONLY",
                vector.path("responseKeyJkt").asText()), "h1").base64Url())
                .isEqualTo(hmac.path("expectedBase64Url").asText());
        assertThat(hasher.digest(command(vector, "different-password",
                vector.path("responseKeyJkt").asText()), "h1").base64Url())
                .isNotEqualTo(hmac.path("expectedBase64Url").asText());
        assertThat(hasher.digest(command(vector, "fixture-password-ONLY",
                vector.path("requestKeyJkt").asText()), "h1").base64Url())
                .isNotEqualTo(hmac.path("expectedBase64Url").asText());
        assertThatThrownBy(() -> hasher.digest(command(vector, "fixture-password-ONLY",
                vector.path("responseKeyJkt").asText()), "missing"))
                .isInstanceOf(InvalidPasswordHmacKeyException.class);
        assertThat(hasher.toString()).doesNotContain(hmac.path("testKeyHex").asText());
    }

    private PasswordSemanticCommand command(JsonNode vector, String password, String recipientJkt) {
        var operation = new PasswordOperationContext(
                UUID.fromString(vector.path("operationId").asText()), "neo-mobile", "ANDROID",
                vector.path("installationId").asText(), "alice",
                UUID.fromString("22222222-2222-4222-8222-222222222222"));
        Digest32 proofId = new ProofDigests().ofProofId("fixture-proof-id");
        var proofs = new VerifiedPasswordProofs(
                new RequestKeyThumbprint(Digest32.fromBase64Url(
                        vector.path("requestKeyJkt").asText())),
                Digest32.fromBase64Url(recipientJkt),
                Digest32.fromBase64Url(vector.path("deviceKeyJkt").asText()),
                new PasswordProofIds(proofId, proofId, proofId), "{}", "{}");
        return new PasswordSemanticCommand(operation,
                new PasswordVerification("alice", password), proofs);
    }
}
