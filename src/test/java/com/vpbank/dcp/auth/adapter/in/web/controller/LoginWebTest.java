package com.vpbank.dcp.auth.adapter.in.web.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.auth.adapter.in.web.common.ErrorMessages;
import com.vpbank.dcp.auth.adapter.in.web.common.SessionFilter;
import com.vpbank.dcp.auth.adapter.in.web.mapper.LoginWebMapper;
import com.vpbank.dcp.auth.adapter.in.web.mapper.SessionWebMapper;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionResult;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginResult;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.in.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.LogoutResult;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
import com.vpbank.dcp.auth.application.port.in.SessionSummary;
import com.vpbank.dcp.auth.config.WebConfiguration;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionStatus;
import java.time.Instant;
import java.util.Optional;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/** Web slice for slice 2: login, logout behind the session filter, extend; use cases mocked. */
@WebMvcTest(controllers = {LoginController.class, SessionController.class, SessionExtensionController.class},
        properties = "auth.login.enabled=true")
@Import({WebConfiguration.class, LoginWebTest.Beans.class})
class LoginWebTest {
    private static final String TOKEN = "k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final Instant IDLE = Instant.parse("2026-10-25T10:15:00Z");
    private static final Instant ABSOLUTE = Instant.parse("2026-10-25T10:20:00Z");
    private static final String LOGIN_BODY = """
            {"userName":"alice","password":"Secret123","channel":"MOBILE","deviceId":"dev-1",
             "tokenEncryptionKey":{"kty":"EC","crv":"P-256","x":"abc","y":"def"}}""";
    private static final String EXTEND_BODY = """
            {"sessionLookup":{"lookupKeyVersion":"k1","lookupDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
             "admissionId":"adm-1","admittedAt":"2026-10-25T10:05:00Z","routeId":"accounts.read"}""";

    @TestConfiguration
    static class Beans {
        @Bean LoginWebMapper loginWebMapper(ErrorMessages errors) { return new LoginWebMapper(errors); }
        @Bean SessionWebMapper sessionWebMapper(ErrorMessages errors) { return new SessionWebMapper(errors); }
        @Bean SessionFilter sessionFilter(CurrentSessionUseCase sessions, ErrorMessages errors,
                                          org.springframework.web.servlet.LocaleResolver locales) {
            return new SessionFilter(sessions, errors, locales);
        }
    }

    @Autowired MockMvc mvc;
    @MockitoBean LoginUseCase login;
    @MockitoBean LogoutUseCase logout;
    @MockitoBean ExtendSessionUseCase extend;
    @MockitoBean CurrentSessionUseCase current;

    @Test
    void loginIs201WithTheEnvelopeAndNeverTheTokenAndNoSessionIsNeeded() throws Exception {
        when(login.login(any())).thenReturn(new LoginResult.Authenticated("eyJ.compact.jwe", new CustomerId("90359"),
                SessionStatus.ACTIVE, IDLE, ABSOLUTE));

        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                .andExpect(status().isCreated())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.data.tokenEnvelope").value("eyJ.compact.jwe"))
                .andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$.data.idleExpiresAt").value("2026-10-25T10:15:00Z"))
                .andExpect(jsonPath("$..token").doesNotExist());
        verifyNoInteractions(current);
        var captor = ArgumentCaptor.forClass(com.vpbank.dcp.auth.application.port.in.LoginCommand.class);
        verify(login).login(captor.capture());
        org.assertj.core.api.Assertions.assertThat(captor.getValue().tokenEncryptionKey()).contains("\"crv\":\"P-256\"");
        org.assertj.core.api.Assertions.assertThat(captor.getValue().channel()).isEqualTo(Channel.MOBILE);
    }

    @Test
    void loginRefusalsHaveTheirStatusCodeAndLocalizedText() throws Exception {
        when(login.login(any())).thenReturn(new LoginResult.InvalidCredentials());
        mvc.perform(post("/api/ns/v1/login").header("Accept-Language", "en")
                        .contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.error.message").value("The user name or password is incorrect"));
        when(login.login(any())).thenReturn(new LoginResult.AccountNotReady());
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.code").value("ACCOUNT_NOT_READY"))
                .andExpect(jsonPath("$.error.message").value(Matchers.startsWith("Tài khoản")));
        when(login.login(any())).thenReturn(new LoginResult.Unavailable());
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.error.code").value("LOGIN_UNAVAILABLE"));
    }

    @Test
    void aBadLoginBodyIs400WithoutEchoingThePassword() throws Exception {
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON)
                        .content(LOGIN_BODY.replace("MOBILE", "FAX")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.error.details[0].field").value("channel"))
                .andExpect(jsonPath("$..value").doesNotExist());
        verifyNoInteractions(login);
    }

    @Test
    void logoutNeedsALiveSessionAndThenEndsIt() throws Exception {
        mvc.perform(post("/api/v1/logout")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("SESSION_REQUIRED"))
                .andExpect(jsonPath("$.error.message").value(Matchers.startsWith("Phiên")));
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer not-a-token"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(logout);

        when(current.resolve(new OpaqueToken(TOKEN))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), null, Channel.MOBILE, IDLE, ABSOLUTE)));
        when(logout.logout(new LogoutCommand(new OpaqueToken(TOKEN)))).thenReturn(new LogoutResult.Ended());
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + TOKEN)).andExpect(status().isNoContent());
        verify(logout).logout(new LogoutCommand(new OpaqueToken(TOKEN)));
    }

    @Test
    void extendIsInternalAndMapsEveryOutcome() throws Exception {
        when(extend.extend(any())).thenReturn(new ExtendSessionResult.Extended(IDLE, ABSOLUTE));
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(EXTEND_BODY))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.idleExpiresAt").value("2026-10-25T10:15:00Z"));
        verifyNoInteractions(current);

        when(extend.extend(any())).thenReturn(new ExtendSessionResult.Gone());
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(EXTEND_BODY))
                .andExpect(status().isGone()).andExpect(jsonPath("$.error.code").value("SESSION_GONE"));
        when(extend.extend(any())).thenReturn(new ExtendSessionResult.Conflict());
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(EXTEND_BODY))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("SESSION_CONFLICT"));
        when(extend.extend(any())).thenReturn(new ExtendSessionResult.Rejected());
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(EXTEND_BODY))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON)
                        .content(EXTEND_BODY.replace("k1", "x1")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.details[0].field").value("sessionLookup.lookupKeyVersion"));
    }
}
