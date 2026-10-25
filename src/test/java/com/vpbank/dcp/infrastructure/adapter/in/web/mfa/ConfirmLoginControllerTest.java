package com.vpbank.dcp.infrastructure.adapter.in.web.mfa;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginUseCase;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginCommand;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginResult;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ConfirmLoginControllerTest {
    private final ConfirmLoginRequestVerifier requests = mock(ConfirmLoginRequestVerifier.class);
    private final ConfirmLoginUseCase logins = mock(ConfirmLoginUseCase.class);
    private final ConfirmLoginController controller = new ConfirmLoginController(requests, logins,
            new PasswordLoginResponseMapper(Clock.fixed(Instant.parse("2026-10-13T00:00:00Z"),
                    ZoneOffset.UTC)));

    @Test
    void invalidProofNeverReachesTotpUseCase() throws Exception {
        String challengeId = "Q0NDQ0NDQ0NDQ0NDQ0NDQw";
        when(requests.verify(any(), any(), any(), any()))
                .thenThrow(new InvalidConfirmLoginRequestException());

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
        ConfirmLoginCommand command = mock(ConfirmLoginCommand.class);
        when(requests.verify(any(), any(), any(), any())).thenReturn(command);
        when(logins.complete(command)).thenReturn(new ConfirmLoginResult.Rejected());

        MockMvcBuilders.standaloneSetup(controller).build().perform(post(
                        "/internal/v1/mfa/challenges/" + challengeId + "/verify")
                        .header("Authorization", "DPoP opaque-token")
                        .header("DPoP", "signed-proof")
                        .contentType("application/json")
                        .content("{\"proof\":\"" + "A".repeat(120) + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.tokenEnvelope").doesNotExist());
    }

    @Test
    void incorrectCodeCanBeRetriedWithinTheSamePendingChallenge() throws Exception {
        String challengeId = "Q0NDQ0NDQ0NDQ0NDQ0NDQw";
        ConfirmLoginCommand command = mock(ConfirmLoginCommand.class);
        when(requests.verify(any(), any(), any(), any())).thenReturn(command);
        when(logins.complete(command)).thenReturn(new ConfirmLoginResult.InvalidCode());

        MockMvcBuilders.standaloneSetup(controller).build().perform(post(
                        "/internal/v1/mfa/challenges/" + challengeId + "/verify")
                        .header("Authorization", "DPoP opaque-token")
                        .header("DPoP", "signed-proof")
                        .contentType("application/json")
                        .content("{\"proof\":\"" + "A".repeat(120) + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.nextAction").value("RETRY_CHALLENGE"))
                .andExpect(jsonPath("$.tokenEnvelope").doesNotExist());
    }
}
