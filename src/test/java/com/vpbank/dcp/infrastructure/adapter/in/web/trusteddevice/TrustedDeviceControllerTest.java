package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.in.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.port.in.trusteddevice.InitTrustedDeviceResult;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceUseCase;
import com.vpbank.dcp.core.port.in.trusteddevice.VerifyTrustedDeviceResult;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.infrastructure.adapter.in.web.BoundedJsonBodyAdvice;
import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiErrorHandler;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.json.JsonMapper;

class TrustedDeviceControllerTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private static final String BASE = "/internal/v1/authentications/trusted-device";
    private static final String JWK = """
            {"kty":"EC","crv":"P-256","x":"%s","y":"%s"}""".formatted("a".repeat(43), "b".repeat(43));
    private final BffCallers callers = mock(BffCallers.class);
    private final TrustedDeviceUseCase useCase = mock(TrustedDeviceUseCase.class);
    private final TrustedDeviceCaller caller = new TrustedDeviceCaller(
            new SessionTokenLookup(new LookupKeyVersion("k1"), Digest32.fromBytes(new byte[32])),
            "neo-mobile", "device-id-1234567890");
    private final MockMvc mvc;

    TrustedDeviceControllerTest() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        JsonMapper json = new JsonMapper();
        mvc = MockMvcBuilders.standaloneSetup(new TrustedDeviceController(callers, useCase,
                        new TrustedDeviceResponseMapper(new PasswordLoginResponseMapper(clock), json),
                        json, clock))
                .setControllerAdvice(new ApiErrorHandler(), new BoundedJsonBodyAdvice()).build();
    }

    @Test
    void initPassesTheNewDeviceKeyAndReturnsTheServerKeyAndChallenge() throws Exception {
        when(callers.require(any(), eq(NOW))).thenReturn(caller);
        when(useCase.init(eq(caller), any(), eq(NOW))).thenReturn(
                new InitTrustedDeviceResult.Started(JWK, "challenge-jwe"));

        mvc.perform(json(post(BASE + "/init"), "{\"devicePublicJwk\":" + JWK + "}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("KEY_EXCHANGE"))
                .andExpect(jsonPath("$.serverPublicJwk.crv").value("P-256"))
                .andExpect(jsonPath("$.challenge").value("challenge-jwe"));

        ArgumentCaptor<String> presented = ArgumentCaptor.forClass(String.class);
        verify(useCase).init(eq(caller), presented.capture(), eq(NOW));
        assertThat(new JsonMapper().readTree(presented.getValue()))
                .isEqualTo(new JsonMapper().readTree(JWK));
    }

    @Test
    void knownDeviceInitSendsNoKey() throws Exception {
        when(callers.require(any(), eq(NOW))).thenReturn(caller);
        when(useCase.init(eq(caller), isNull(), eq(NOW))).thenReturn(
                new InitTrustedDeviceResult.Rejected());

        mvc.perform(json(post(BASE + "/init"), "{}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.nextAction").value("START_NEW_LOGIN"));
    }

    @Test
    void wrongChallengeTellsHowManyAttemptsAreLeft() throws Exception {
        when(callers.require(any(), eq(NOW))).thenReturn(caller);
        when(useCase.verify(caller, "r".repeat(64), NOW)).thenReturn(
                new VerifyTrustedDeviceResult.WrongChallenge(2));

        mvc.perform(json(post(BASE + "/verify"), "{\"challengeResponse\":\"" + "r".repeat(64) + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("WRONG_CHALLENGE"))
                .andExpect(jsonPath("$.attemptsLeft").value(2))
                .andExpect(jsonPath("$.nextAction").value("RETRY"));
    }

    @Test
    void provenKeyReturnsTheMfaTransaction() throws Exception {
        when(callers.require(any(), eq(NOW))).thenReturn(caller);
        when(useCase.verify(caller, "r".repeat(64), NOW)).thenReturn(
                new VerifyTrustedDeviceResult.MfaRequired("mfa-transaction-1"));

        mvc.perform(json(post(BASE + "/verify"), "{\"challengeResponse\":\"" + "r".repeat(64) + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.mfaTransactionId").value("mfa-transaction-1"))
                .andExpect(jsonPath("$.attemptsLeft").doesNotExist());
    }

    @Test
    void confirmBeforeMfaPassesAsksTheAppToCompleteMfa() throws Exception {
        when(callers.require(any(), eq(NOW))).thenReturn(caller);
        when(useCase.confirm(caller, NOW)).thenReturn(new ConfirmTrustedDeviceResult.MfaPending());

        mvc.perform(post(BASE + "/confirm"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MFA_NOT_PASSED"))
                .andExpect(jsonPath("$.nextAction").value("COMPLETE_MFA"));
    }

    @Test
    void rejectedCallerNeverReachesTheUseCase() throws Exception {
        when(callers.require(any(), eq(NOW))).thenThrow(new RejectedBffCallerException());

        mvc.perform(post(BASE + "/confirm"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"));
        verifyNoInteractions(useCase);
    }

    @Test
    void invalidBodyIsABadRequest() throws Exception {
        mvc.perform(json(post(BASE + "/verify"), "{\"challengeResponse\":\"short\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(json(post(BASE + "/init"), "{\"devicePublicJwk\":{\"kty\":\"RSA\"}}"))
                .andExpect(status().isBadRequest());
        mvc.perform(json(post(BASE + "/init"), "{\"pad\":\"" + "x".repeat(70_000) + "\"}"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(useCase);
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request,
                                                      String body) {
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }
}
