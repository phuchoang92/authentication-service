package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

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

import com.vpbank.dcp.core.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.trusteddevice.InitTrustedDeviceResult;
import com.vpbank.dcp.core.session.TrustedDeviceCaller;
import com.vpbank.dcp.core.trusteddevice.TrustedDeviceService;
import com.vpbank.dcp.core.trusteddevice.VerifyTrustedDeviceResult;
import com.vpbank.dcp.core.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.trusteddevice.BffCallerAssertions;
import com.vpbank.dcp.infrastructure.adapter.in.web.BoundedJsonBodyAdvice;
import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiErrorHandler;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TrustedDeviceControllerTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private static final String BASE = "/internal/v1/authentications/trusted-device";
    private static final String KEY = "A".repeat(1622);
    private static final String SUITE = "DCP-HPKE-XWING-SHA256-AES256GCM-V1";
    private static final UUID ENROLLMENT = UUID.fromString("7d1c6a0e-5b3f-4a59-9d8e-1f2a3b4c5d6e");
    private static final String PROOF_BODY = "{\"enrollmentId\":\"" + ENROLLMENT
            + "\",\"keyExchangeProof\":\"" + "r".repeat(64) + "\"}";
    private final BffCallerAssertions assertions = mock(BffCallerAssertions.class);
    private final TrustedDeviceService trustedDevices = mock(TrustedDeviceService.class);
    private final TrustedDeviceCaller caller = new TrustedDeviceCaller(
            UUID.randomUUID(), "neo-mobile", "device-id-1234567890");
    private final MockMvc mvc;

    TrustedDeviceControllerTest() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        mvc = MockMvcBuilders.standaloneSetup(new TrustedDeviceController(assertions, trustedDevices,
                        new TrustedDeviceResponseMapper(new PasswordLoginResponseMapper(clock)), clock))
                .setControllerAdvice(new ApiErrorHandler(), new BoundedJsonBodyAdvice()).build();
    }

    @Test
    void initPassesTheNewDeviceKeyAndReturnsTheServerKeyAndChallenge() throws Exception {
        when(assertions.accept("bff-assertion", NOW)).thenReturn(Optional.of(caller));
        when(trustedDevices.init(caller, KEY, NOW)).thenReturn(new InitTrustedDeviceResult.Started(
                ENROLLMENT, SUITE, "S".repeat(1622), "protected-challenge"));

        mvc.perform(json(bearer(post(BASE + "/init")), "{\"clientPublicKey\":\"" + KEY + "\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("KEY_EXCHANGE"))
                .andExpect(jsonPath("$.enrollmentId").value(ENROLLMENT.toString()))
                .andExpect(jsonPath("$.suite").value(SUITE))
                .andExpect(jsonPath("$.publicKey").value("S".repeat(1622)))
                .andExpect(jsonPath("$.protectedChallenge").value("protected-challenge"));
    }

    @Test
    void knownDeviceInitSendsNoKey() throws Exception {
        when(assertions.accept("bff-assertion", NOW)).thenReturn(Optional.of(caller));
        when(trustedDevices.init(eq(caller), isNull(), eq(NOW))).thenReturn(
                new InitTrustedDeviceResult.Rejected());

        mvc.perform(json(bearer(post(BASE + "/init")), "{}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.nextAction").value("START_NEW_LOGIN"));
    }

    @Test
    void wrongChallengeTellsHowManyAttemptsAreLeft() throws Exception {
        when(assertions.accept("bff-assertion", NOW)).thenReturn(Optional.of(caller));
        when(trustedDevices.verify(caller, ENROLLMENT, "r".repeat(64), NOW)).thenReturn(
                new VerifyTrustedDeviceResult.WrongChallenge(2));

        mvc.perform(json(bearer(post(BASE + "/verify")), PROOF_BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("WRONG_CHALLENGE"))
                .andExpect(jsonPath("$.attemptsLeft").value(2))
                .andExpect(jsonPath("$.nextAction").value("RETRY"));
    }

    @Test
    void provenKeyReturnsTheMfaTransaction() throws Exception {
        when(assertions.accept("bff-assertion", NOW)).thenReturn(Optional.of(caller));
        when(trustedDevices.verify(caller, ENROLLMENT, "r".repeat(64), NOW)).thenReturn(
                new VerifyTrustedDeviceResult.MfaRequired("mfa-transaction-1"));

        mvc.perform(json(bearer(post(BASE + "/verify")), PROOF_BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.mfaTransactionId").value("mfa-transaction-1"))
                .andExpect(jsonPath("$.attemptsLeft").doesNotExist());
    }

    @Test
    void confirmBeforeMfaPassesAsksTheAppToCompleteMfa() throws Exception {
        when(assertions.accept("bff-assertion", NOW)).thenReturn(Optional.of(caller));
        when(trustedDevices.confirm(caller, NOW)).thenReturn(new ConfirmTrustedDeviceResult.MfaPending());

        mvc.perform(bearer(post(BASE + "/confirm")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("MFA_NOT_PASSED"))
                .andExpect(jsonPath("$.nextAction").value("COMPLETE_MFA"));
    }

    @Test
    void rejectedCallerNeverReachesTheUseCase() throws Exception {
        when(assertions.accept("bff-assertion", NOW)).thenReturn(Optional.empty());

        mvc.perform(bearer(post(BASE + "/confirm")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"));
        verifyNoInteractions(trustedDevices);
    }

    @Test
    void anythingButOneBearerAssertionIsRejectedBeforeItIsChecked() throws Exception {
        for (MockHttpServletRequestBuilder request : List.of(post(BASE + "/confirm"),
                post(BASE + "/confirm").header("Authorization", "Basic bff-assertion"),
                post(BASE + "/confirm").header("Authorization", "Bearer a", "Bearer b"),
                bearer(post(BASE + "/confirm")).header("DPoP", "proof"),
                post(BASE + "/confirm").header("Authorization", "Bearer " + "x".repeat(5000)))) {
            mvc.perform(request).andExpect(status().isUnauthorized());
        }
        verifyNoInteractions(assertions, trustedDevices);
    }

    @Test
    void unrecordableAssertionUseIsUnavailable() throws Exception {
        when(assertions.accept("bff-assertion", NOW))
                .thenThrow(new ReplayAuthorityUnavailableException());

        mvc.perform(bearer(post(BASE + "/confirm"))).andExpect(status().isServiceUnavailable());
        verifyNoInteractions(trustedDevices);
    }

    @Test
    void invalidBodyIsABadRequest() throws Exception {
        for (String verify : List.of(
                "{\"enrollmentId\":\"" + ENROLLMENT + "\",\"keyExchangeProof\":\"short\"}",
                "{\"keyExchangeProof\":\"" + "r".repeat(64) + "\"}",
                "{\"enrollmentId\":\"not-a-uuid\",\"keyExchangeProof\":\"" + "r".repeat(64) + "\"}")) {
            mvc.perform(json(bearer(post(BASE + "/verify")), verify)).andExpect(status().isBadRequest());
        }
        for (String key : List.of(KEY.substring(1), KEY + "A", "+" + KEY.substring(1))) {
            mvc.perform(json(bearer(post(BASE + "/init")), "{\"clientPublicKey\":\"" + key + "\"}"))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(json(bearer(post(BASE + "/init")), "{\"pad\":\"" + "x".repeat(70_000) + "\"}"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(trustedDevices);
    }

    private static MockHttpServletRequestBuilder bearer(MockHttpServletRequestBuilder request) {
        return request.header("Authorization", "Bearer bff-assertion");
    }

    private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder request,
                                                      String body) {
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }
}
