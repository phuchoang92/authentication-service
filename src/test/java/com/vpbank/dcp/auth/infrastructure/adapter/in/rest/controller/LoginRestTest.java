package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.port.in.ApprovalStatusUseCase;
import com.vpbank.dcp.auth.application.port.in.ApproveEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.AuthorizeEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.ClaimEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.ConfirmEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.ExtendSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.InitEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.IssueCaptchaUseCase;
import com.vpbank.dcp.auth.application.port.in.ListDevicesUseCase;
import com.vpbank.dcp.auth.application.port.in.ListPendingDevicesUseCase;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.in.LogoutUseCase;
import com.vpbank.dcp.auth.application.port.in.RequestApprovalUseCase;
import com.vpbank.dcp.auth.application.port.in.UnlockPasswordUseCase;
import com.vpbank.dcp.auth.application.port.in.VerifyEnrollmentUseCase;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.application.result.CaptchaChallenge;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.ExtendSessionResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.application.result.PendingDeviceSummary;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.application.result.SessionSummary;
import com.vpbank.dcp.auth.application.result.UnlockPasswordResult;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.DeviceApprovalRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.LoginRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.PasswordUnlockRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.SessionRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.TrustedDeviceRestMapper;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Instant;
import java.util.List;
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
@WebMvcTest(controllers = {LoginController.class, SessionController.class, SessionExtensionController.class,
        CaptchaController.class, PasswordUnlockController.class, DeviceController.class, TrustedDeviceController.class,
        DeviceApprovalController.class},
        properties = "auth.login.enabled=true")
@Import({RestConfiguration.class, LoginRestTest.Beans.class})
class LoginRestTest {
    private static final String TOKEN = "k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final Instant IDLE = Instant.parse("2026-10-25T10:15:00Z");
    private static final Instant ABSOLUTE = Instant.parse("2026-10-25T10:20:00Z");
    private static final String LOGIN_BODY = """
            {"userName":"alice","password":"Secret123","channel":"MOBILE","deviceId":"dev-1","platform":"ANDROID",
             "tokenEncryptionKey":{"kty":"EC","crv":"P-256","x":"abc","y":"def"}}""";
    private static final String EXTEND_BODY = """
            {"sessionLookup":{"lookupKeyVersion":"k1","lookupDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
             "admissionId":"adm-1","admittedAt":"2026-10-25T10:05:00Z","routeId":"accounts.read"}""";

    @TestConfiguration
    static class Beans {
        @Bean LoginRestMapper loginRestMapper(ErrorMessages errors) { return new LoginRestMapper(errors); }
        @Bean SessionRestMapper sessionRestMapper(ErrorMessages errors) { return new SessionRestMapper(errors); }
        @Bean PasswordUnlockRestMapper passwordUnlockRestMapper(ErrorMessages errors) { return new PasswordUnlockRestMapper(errors); }
        @Bean TrustedDeviceRestMapper trustedDeviceRestMapper(ErrorMessages errors) { return new TrustedDeviceRestMapper(errors); }
        @Bean DeviceApprovalRestMapper deviceApprovalRestMapper(ErrorMessages errors) { return new DeviceApprovalRestMapper(errors); }
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
    @MockitoBean IssueCaptchaUseCase captchas;
    @MockitoBean UnlockPasswordUseCase unlock;
    @MockitoBean ListDevicesUseCase devices;
    @MockitoBean InitEnrollmentUseCase initEnrollment;
    @MockitoBean VerifyEnrollmentUseCase verifyEnrollment;
    @MockitoBean ConfirmEnrollmentUseCase confirmEnrollment;
    @MockitoBean RequestApprovalUseCase requestApproval;
    @MockitoBean ApprovalStatusUseCase approvalStatus;
    @MockitoBean ListPendingDevicesUseCase listPending;
    @MockitoBean ApproveEnrollmentUseCase approveEnrollment;
    @MockitoBean AuthorizeEnrollmentUseCase authorizeEnrollment;
    @MockitoBean ClaimEnrollmentUseCase claimEnrollment;

    @Test
    void approvalRoutesPassOpaqueIdsAndMapTheirOutcomes() throws Exception {
        String restrictedToken = "k1." + "C".repeat(43);
        when(current.resolve(new OpaqueToken(TOKEN))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), new com.vpbank.dcp.auth.domain.model.DeviceId("dev-1"), Channel.MOBILE,
                SessionStatus.ACTIVE, IDLE, ABSOLUTE)));
        when(current.resolve(new OpaqueToken(restrictedToken))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), new com.vpbank.dcp.auth.domain.model.DeviceId("watch-3"), Channel.MOBILE,
                SessionStatus.NEED_TRUSTED_DEVICE, IDLE, IDLE)));
        EnrollmentId enrollmentId = EnrollmentId.random();

        // The new device: request (restricted token), status poll.
        mvc.perform(post("/api/v1/trusted-device/request").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(requestApproval);
        when(requestApproval.request(any())).thenReturn(new RequestApprovalResult.WaitingApproval(enrollmentId, IDLE));
        mvc.perform(post("/api/v1/trusted-device/request").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"devicePublicJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"w\",\"y\":\"w\"},\"platform\":\"IOS\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("WAITING_APPROVAL"))
                .andExpect(jsonPath("$.data.enrollmentId").value(enrollmentId.value().toString()));
        var requestCaptor = ArgumentCaptor.forClass(com.vpbank.dcp.auth.application.command.RequestApprovalCommand.class);
        verify(requestApproval).request(requestCaptor.capture());
        org.assertj.core.api.Assertions.assertThat(requestCaptor.getValue().platform()).isEqualTo(DevicePlatform.IOS);
        org.assertj.core.api.Assertions.assertThat(requestCaptor.getValue().devicePublicJwk()).contains("\"crv\":\"P-256\"");
        when(requestApproval.request(any())).thenReturn(new RequestApprovalResult.TooManyPending());
        mvc.perform(post("/api/v1/trusted-device/request").header("Authorization", "Bearer " + restrictedToken)
                        .header("Accept-Language", "en").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("TOO_MANY_PENDING_DEVICES"));
        when(approvalStatus.status(any())).thenReturn(new ApprovalStatusResult.Status(enrollmentId,
                EnrollmentState.WAITING_AUTHORIZATION, IDLE));
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/trusted-device/status")
                        .header("Authorization", "Bearer " + restrictedToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("WAITING_AUTHORIZATION"));

        // The primary device: pending list, approve, authorize; a non-primary caller is refused by the use case.
        when(listPending.pending(any())).thenReturn(new ListPendingDevicesResult.Pending(List.of(new PendingDeviceSummary(
                enrollmentId, new com.vpbank.dcp.auth.domain.model.DeviceId("watch-3000"), DevicePlatform.IOS,
                EnrollmentState.WAITING_APPROVAL, IDLE))));
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/trusted-device/pending")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].enrollmentId").value(enrollmentId.value().toString()))
                .andExpect(jsonPath("$.data[0].deviceId").value("…3000"))
                .andExpect(jsonPath("$.data[0].platform").value("IOS"));
        when(approveEnrollment.approve(any())).thenReturn(new ApproveEnrollmentResult.NotPrimaryDevice());
        mvc.perform(post("/api/v1/trusted-device/pending/" + enrollmentId.value() + "/approve")
                        .header("Authorization", "Bearer " + TOKEN).header("Accept-Language", "en"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.code").value("NOT_PRIMARY_DEVICE"))
                .andExpect(jsonPath("$.error.message").value("Only the primary device can approve a new device"));
        mvc.perform(post("/api/v1/trusted-device/pending/not-a-uuid/approve").header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"));
        when(approveEnrollment.approve(any())).thenReturn(new ApproveEnrollmentResult.MfaRequired("mfa-7", IDLE));
        mvc.perform(post("/api/v1/trusted-device/pending/" + enrollmentId.value() + "/approve")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.data.mfaTransactionId").value("mfa-7"));
        var approveCaptor = ArgumentCaptor.forClass(com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand.class);
        verify(approveEnrollment, org.mockito.Mockito.times(2)).approve(approveCaptor.capture());
        org.assertj.core.api.Assertions.assertThat(approveCaptor.getValue().enrollmentId()).isEqualTo(enrollmentId);
        when(authorizeEnrollment.authorize(any())).thenReturn(new AuthorizeEnrollmentResult.Authorized(enrollmentId, "qr-token", IDLE));
        mvc.perform(post("/api/v1/trusted-device/pending/" + enrollmentId.value() + "/authorize")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("WAITING_AUTHORIZATION"))
                .andExpect(jsonPath("$.data.authorizationToken").value("qr-token"));
        when(authorizeEnrollment.authorize(any())).thenReturn(new AuthorizeEnrollmentResult.MfaPending());
        mvc.perform(post("/api/v1/trusted-device/pending/" + enrollmentId.value() + "/authorize")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("MFA_NOT_PASSED"));

        // The new device claims: wrong token detail, then success.
        String claimBody = "{\"authorizationToken\":\"qr-token\",\"tokenEncryptionKey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\"}}";
        when(claimEnrollment.claim(any())).thenReturn(new ClaimEnrollmentResult.WrongAuthorization(4));
        mvc.perform(post("/api/v1/trusted-device/claim").header("Authorization", "Bearer " + restrictedToken)
                        .header("Accept-Language", "en").contentType(MediaType.APPLICATION_JSON).content(claimBody))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error.code").value("WRONG_AUTHORIZATION"))
                .andExpect(jsonPath("$.error.message").value("The QR code is not correct"))
                .andExpect(jsonPath("$.error.details[0].field").value("attemptsLeft"))
                .andExpect(jsonPath("$.error.details[0].message").value("4"));
        when(claimEnrollment.claim(any())).thenReturn(new ClaimEnrollmentResult.AuthorizationExpired());
        mvc.perform(post("/api/v1/trusted-device/claim").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(claimBody))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error.code").value("AUTHORIZATION_EXPIRED"));
        when(claimEnrollment.claim(any())).thenReturn(new ClaimEnrollmentResult.Trusted("eyJ.env", IDLE, ABSOLUTE));
        mvc.perform(post("/api/v1/trusted-device/claim").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(claimBody))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$.data.tokenEnvelope").value("eyJ.env"))
                .andExpect(jsonPath("$..token").doesNotExist());
        mvc.perform(post("/api/v1/trusted-device/claim").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"authorizationToken\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void trustedDeviceRoutesNeedARestrictedSessionAndMapTheirOutcomes() throws Exception {
        String restrictedToken = "k1." + "C".repeat(43);
        when(current.resolve(new OpaqueToken(TOKEN))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), new com.vpbank.dcp.auth.domain.model.DeviceId("dev-1"), Channel.MOBILE,
                SessionStatus.ACTIVE, IDLE, ABSOLUTE)));
        when(current.resolve(new OpaqueToken(restrictedToken))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), new com.vpbank.dcp.auth.domain.model.DeviceId("tablet-2"), Channel.MOBILE,
                SessionStatus.NEED_TRUSTED_DEVICE, IDLE, IDLE)));
        String initBody = "{\"devicePublicJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"},\"platform\":\"IOS\"}";

        // No session at all: the filter answers before the controller.
        mvc.perform(post("/api/v1/trusted-device/init").contentType(MediaType.APPLICATION_JSON).content(initBody))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error.code").value("SESSION_REQUIRED"));
        verifyNoInteractions(initEnrollment);

        // A restricted session passes the filter; the use case answers.
        EnrollmentId enrollmentId = EnrollmentId.random();
        when(initEnrollment.init(any())).thenReturn(new InitEnrollmentResult.KeyExchange(enrollmentId,
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"sx\",\"y\":\"sy\"}", "eyJ.challenge", IDLE));
        mvc.perform(post("/api/v1/trusted-device/init").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(initBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("KEY_EXCHANGE"))
                .andExpect(jsonPath("$.data.enrollmentId").value(enrollmentId.value().toString()))
                .andExpect(jsonPath("$.data.serverPublicJwk.x").value("sx"))
                .andExpect(jsonPath("$.data.challenge").value("eyJ.challenge"));
        var initCaptor = ArgumentCaptor.forClass(com.vpbank.dcp.auth.application.command.InitEnrollmentCommand.class);
        verify(initEnrollment).init(initCaptor.capture());
        org.assertj.core.api.Assertions.assertThat(initCaptor.getValue().token().value()).isEqualTo(restrictedToken);
        org.assertj.core.api.Assertions.assertThat(initCaptor.getValue().platform()).isEqualTo(DevicePlatform.IOS);

        // An ACTIVE session reaches the use case, which refuses: 409.
        when(initEnrollment.init(any())).thenReturn(new InitEnrollmentResult.Conflict());
        mvc.perform(post("/api/v1/trusted-device/init").header("Authorization", "Bearer " + TOKEN)
                        .header("Accept-Language", "en").contentType(MediaType.APPLICATION_JSON).content(initBody))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("STATE_CONFLICT"))
                .andExpect(jsonPath("$.error.message").value("This step is not valid in the current state"));

        when(verifyEnrollment.verify(any())).thenReturn(new VerifyEnrollmentResult.WrongChallenge(1));
        mvc.perform(post("/api/v1/trusted-device/verify").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"challengeResponse\":\"eyJ.response\"}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error.code").value("WRONG_CHALLENGE"))
                .andExpect(jsonPath("$.error.details[0].field").value("attemptsLeft"))
                .andExpect(jsonPath("$.error.details[0].message").value("1"));
        mvc.perform(post("/api/v1/trusted-device/verify").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error.details[0].field").value("challengeResponse"));

        when(confirmEnrollment.confirm(any())).thenReturn(new ConfirmEnrollmentResult.Trusted("eyJ.env", IDLE, ABSOLUTE));
        mvc.perform(post("/api/v1/trusted-device/confirm").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokenEncryptionKey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$.data.tokenEnvelope").value("eyJ.env"))
                .andExpect(jsonPath("$..token").doesNotExist());
        when(confirmEnrollment.confirm(any())).thenReturn(new ConfirmEnrollmentResult.MfaPending());
        mvc.perform(post("/api/v1/trusted-device/confirm").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tokenEncryptionKey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}}"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("MFA_NOT_PASSED"));
    }

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
        var captor = ArgumentCaptor.forClass(com.vpbank.dcp.auth.application.command.LoginCommand.class);
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
        when(login.login(any())).thenReturn(new LoginResult.AccountLocked());
        mvc.perform(post("/api/ns/v1/login").header("Accept-Language", "en")
                        .contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                .andExpect(status().isLocked()).andExpect(jsonPath("$.error.code").value("ACCOUNT_LOCKED"))
                .andExpect(jsonPath("$.error.message").value("The account is locked after too many failed logins"))
                .andExpect(jsonPath("$.error.lockedUntil").doesNotExist());
        when(login.login(any())).thenReturn(new LoginResult.CaptchaRequired());
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                .andExpect(status().isPreconditionRequired()).andExpect(jsonPath("$.error.code").value("CAPTCHA_REQUIRED"));
    }

    @Test
    void aCaptchaIsIssuedForAUserNameAndSentBackWithTheLogin() throws Exception {
        com.vpbank.dcp.auth.domain.model.CaptchaId id = com.vpbank.dcp.auth.domain.model.CaptchaId.random();
        when(captchas.issue(new com.vpbank.dcp.auth.domain.model.UserName("alice")))
                .thenReturn(new CaptchaChallenge(id, new byte[]{1, 2, 3}, IDLE));
        mvc.perform(post("/api/ns/v1/login/captcha").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"alice\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.captchaId").value(id.toString()))
                .andExpect(jsonPath("$.data.image").value("AQID"))
                .andExpect(jsonPath("$.data.expiresAt").value("2026-10-25T10:15:00Z"));
        verifyNoInteractions(current);

        when(login.login(any())).thenReturn(new LoginResult.InvalidCredentials());
        String withCaptcha = LOGIN_BODY.replace("\"deviceId\":\"dev-1\",",
                "\"deviceId\":\"dev-1\",\"captcha\":{\"captchaId\":\"" + id + "\",\"answer\":\"ab3cd\"},");
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(withCaptcha))
                .andExpect(status().isUnauthorized());
        var captor = ArgumentCaptor.forClass(com.vpbank.dcp.auth.application.command.LoginCommand.class);
        verify(login).login(captor.capture());
        org.assertj.core.api.Assertions.assertThat(captor.getValue().captcha().captchaId()).isEqualTo(id);
        org.assertj.core.api.Assertions.assertThat(captor.getValue().captcha().answer().normalized()).isEqualTo("AB3CD");

        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON)
                        .content(withCaptcha.replace("ab3cd", "a!")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.details[0].field").value("captcha.answer"));
    }

    @Test
    void anActiveSessionListsItsDevicesMaskedWhileARestrictedOneMayOnlyLogOut() throws Exception {
        String restrictedToken = "k1." + "B".repeat(43);
        when(current.resolve(new OpaqueToken(TOKEN))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), new com.vpbank.dcp.auth.domain.model.DeviceId("dev-1"), Channel.MOBILE,
                SessionStatus.ACTIVE, IDLE, ABSOLUTE)));
        when(current.resolve(new OpaqueToken(restrictedToken))).thenReturn(Optional.of(new SessionSummary(SessionId.random(),
                new CustomerId("90359"), new com.vpbank.dcp.auth.domain.model.DeviceId("tablet-99"), Channel.MOBILE,
                SessionStatus.NEED_TRUSTED_DEVICE, IDLE, IDLE)));
        when(devices.list(new CustomerId("90359"), Channel.MOBILE)).thenReturn(java.util.List.of(DeviceSummary.builder()
                .deviceId(new com.vpbank.dcp.auth.domain.model.DeviceId("dev-12345678"))
                .platform(DevicePlatform.ANDROID)
                .status(DeviceStatus.ACTIVE)
                .trustLevel(TrustLevel.TRUSTED).primary(true)
                .trustedAt(IDLE).expiresAt(ABSOLUTE).lastLoginAt(IDLE).build()));

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/devices")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].deviceId").value("…5678"))
                .andExpect(jsonPath("$.data[0].primary").value(true))
                .andExpect(jsonPath("$.data[0].status").value("ACTIVE"));

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/devices")
                        .header("Authorization", "Bearer " + restrictedToken).header("Accept-Language", "en"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("DEVICE_TRUST_REQUIRED"))
                .andExpect(jsonPath("$.error.message").value("This device is not trusted yet, please complete device verification"));
        when(logout.logout(any())).thenReturn(new LogoutResult.Ended());
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + restrictedToken)).andExpect(status().isNoContent());
    }

    @Test
    void unlockIsInternalAndMapsEveryOutcome() throws Exception {
        when(unlock.unlock(new CustomerId("90359"))).thenReturn(new UnlockPasswordResult.Unlocked());
        mvc.perform(post("/internal/v1/customers/90359/password-unlock")).andExpect(status().isNoContent());
        verifyNoInteractions(current);

        when(unlock.unlock(new CustomerId("00000"))).thenReturn(new UnlockPasswordResult.UnknownCustomer());
        mvc.perform(post("/internal/v1/customers/00000/password-unlock").header("Accept-Language", "en"))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.error.code").value("CUSTOMER_UNKNOWN"))
                .andExpect(jsonPath("$.error.message").value("The customer is unknown"));
        mvc.perform(post("/internal/v1/customers/not%20valid/password-unlock")).andExpect(status().isBadRequest());
        verify(unlock, org.mockito.Mockito.times(2)).unlock(any());
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
                new CustomerId("90359"), null, Channel.MOBILE, SessionStatus.ACTIVE, IDLE, ABSOLUTE)));
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
