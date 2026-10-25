package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.core.port.in.mfa.CompleteTotpLoginUseCase;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginCommand;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginResult;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TotpLoginControllerTest {
    private final TotpLoginRequestVerifier requests = mock(TotpLoginRequestVerifier.class);
    private final CompleteTotpLoginUseCase logins = mock(CompleteTotpLoginUseCase.class);
    private final TotpLoginController controller = new TotpLoginController(requests, logins,
            new PasswordLoginResponseMapper(Clock.fixed(Instant.parse("2026-10-13T00:00:00Z"),
                    ZoneOffset.UTC)));

    @Test
    void invalidProofNeverReachesTotpUseCase() throws Exception {
        String challengeId = "Q0NDQ0NDQ0NDQ0NDQ0NDQw";
        when(requests.verify(any(), any(), any(), any()))
                .thenThrow(new InvalidTotpLoginRequestException());

        MockMvcBuilders.standaloneSetup(controller).build().perform(post(
                        "/internal/v1/mfa/challenges/" + challengeId + "/verify")
                        .header("Authorization", "DPoP opaque-token")
                        .header("DPoP", "signed-proof")
                        .contentType("application/json")
                        .content("{\"proof\":\"" + "A".repeat(120) + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"));
        verify(logins, never()).complete(any());
    }

    @Test
    void rejectedTotpDoesNotReturnEncryptedActiveToken() throws Exception {
        String challengeId = "Q0NDQ0NDQ0NDQ0NDQ0NDQw";
        TotpLoginCommand command = mock(TotpLoginCommand.class);
        when(requests.verify(any(), any(), any(), any())).thenReturn(command);
        when(logins.complete(command)).thenReturn(new TotpLoginResult.Rejected());

        MockMvcBuilders.standaloneSetup(controller).build().perform(post(
                        "/internal/v1/mfa/challenges/" + challengeId + "/verify")
                        .header("Authorization", "DPoP opaque-token")
                        .header("DPoP", "signed-proof")
                        .contentType("application/json")
                        .content("{\"proof\":\"" + "A".repeat(120) + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.tokenEnvelope").doesNotExist());
    }
}
