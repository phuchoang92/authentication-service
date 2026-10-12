package com.vpbank.dcp.infrastructure.adapter.in.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginRequest;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class ForwardedPublicRequestTest {
    private final JsonMapper json = JsonMapper.builder().build();

    @Test
    void passwordRequestKeepsTheOriginalJsonShape() {
        String original = "{\"method\":\"POST\",\"publicUri\":\"https://api.bank.example/path\","
                + "\"dpopProof\":\"proof-secret\",\"opaqueToken\":null,"
                + "\"bodyBase64\":\"Ym9keQ\",\"idempotencyKey\":\"operation-1\"}";

        PasswordLoginRequest login = json.readValue("{\"original\":" + original + "}",
                PasswordLoginRequest.class);
        assertThat(login.original().bodyBase64()).isEqualTo("Ym9keQ");
        assertThat(json.readTree(json.writeValueAsString(login)).get("original"))
                .isEqualTo(json.readTree(original));
        assertThat(login.toString()).doesNotContain("proof-secret");
        assertThat(login.original().toString()).doesNotContain("proof-secret");
    }
}
