package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.PendingDeviceSummary;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ClaimEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.RequestApprovalRequest;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class DeviceApprovalRestMapperTest {
    private static final String TOKEN = "k1." + "A".repeat(43);
    private static final Instant EXPIRES = Instant.parse("2026-10-26T10:10:00Z");
    private static final EnrollmentId ENROLLMENT = EnrollmentId.random();
    private static final Map<String, Object> JWK = Map.of("kty", "EC");
    private final DeviceApprovalRestMapper mapper =
            new DeviceApprovalRestMapper(new ErrorMessages(RestConfiguration.errorMessageSource()));

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void commandsCarryTypedIdsAndJwkTextAndRefuseMalformedInput() {
        RequestApprovalCommand request = mapper.toRequestCommand(TOKEN, new RequestApprovalRequest(JWK, "IOS"));
        assertThat(request.devicePublicJwk()).isEqualTo("{\"kty\":\"EC\"}");
        assertThat(request.platform()).isEqualTo(DevicePlatform.IOS);
        assertThat(mapper.toRequestCommand(TOKEN, new RequestApprovalRequest(null, null)).devicePublicJwk()).isNull();

        ApproveEnrollmentCommand approve = mapper.toApproveCommand(TOKEN, ENROLLMENT.value().toString());
        assertThat(approve.enrollmentId()).isEqualTo(ENROLLMENT);
        assertThatThrownBy(() -> mapper.toApproveCommand(TOKEN, "not-a-uuid")).isInstanceOf(InvalidRequestException.class);
        assertThatThrownBy(() -> mapper.toAuthorizeCommand("bad-token", ENROLLMENT.value().toString()))
                .isInstanceOf(InvalidRequestException.class);

        ClaimEnrollmentCommand claim = mapper.toClaimCommand(TOKEN, new ClaimEnrollmentRequest("qr", JWK));
        assertThat(claim.authorizationToken()).isEqualTo("qr");
        assertThat(claim.tokenEncryptionKey()).isEqualTo("{\"kty\":\"EC\"}");
        assertThatThrownBy(() -> mapper.toClaimCommand(TOKEN, new ClaimEnrollmentRequest("qr", Map.of("kty", 1))))
                .isInstanceOf(InvalidRequestException.class);
    }

    @Test
    void everyOutcomeHasItsStatusAndCodeAndIdsAreOpaqueStrings() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        var waiting = mapper.toResponse(new RequestApprovalResult.WaitingApproval(ENROLLMENT, EXPIRES));
        assertThat(waiting.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(waiting.getBody().data().status()).isEqualTo("WAITING_APPROVAL");
        assertThat(waiting.getBody().data().enrollmentId()).isEqualTo(ENROLLMENT.value().toString());
        assertFailure(mapper.toResponse(new RequestApprovalResult.DeviceKeyRequired()), HttpStatus.BAD_REQUEST, "DEVICE_KEY_REQUIRED");
        assertFailure(mapper.toResponse(new RequestApprovalResult.TooManyPending()), HttpStatus.CONFLICT, "TOO_MANY_PENDING_DEVICES");
        assertFailure(mapper.toResponse(new RequestApprovalResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");
        assertFailure(mapper.toResponse(new RequestApprovalResult.SessionGone()), HttpStatus.UNAUTHORIZED, "SESSION_REQUIRED");
        assertFailure(mapper.toResponse(new RequestApprovalResult.Unavailable()), HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");

        var status = mapper.toResponse(new ApprovalStatusResult.Status(ENROLLMENT, EnrollmentState.FAILED, EXPIRES));
        assertThat(status.getBody().data().status()).isEqualTo("FAILED");
        assertFailure(mapper.toResponse(new ApprovalStatusResult.NoRequest()), HttpStatus.CONFLICT, "STATE_CONFLICT");

        var pending = mapper.toResponse(new ListPendingDevicesResult.Pending(List.of(new PendingDeviceSummary(ENROLLMENT,
                new DeviceId("watch-30001"), DevicePlatform.IOS, EnrollmentState.WAITING_APPROVAL, EXPIRES))));
        assertThat(pending.getBody().data()).hasSize(1);
        assertThat(pending.getBody().data().get(0).deviceId()).isEqualTo("…0001");
        assertThat(pending.getBody().data().get(0).enrollmentId()).isEqualTo(ENROLLMENT.value().toString());
        assertFailure(mapper.toResponse(new ListPendingDevicesResult.NotPrimaryDevice()), HttpStatus.FORBIDDEN, "NOT_PRIMARY_DEVICE");

        var mfaRequired = mapper.toResponse(new ApproveEnrollmentResult.MfaRequired("mfa-7", EXPIRES));
        assertThat(mfaRequired.getBody().data().status()).isEqualTo("MFA_REQUIRED");
        assertFailure(mapper.toResponse(new ApproveEnrollmentResult.NotPrimaryDevice()), HttpStatus.FORBIDDEN, "NOT_PRIMARY_DEVICE");
        assertFailure(mapper.toResponse(new ApproveEnrollmentResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");
        assertFailure(mapper.toResponse(new ApproveEnrollmentResult.NoUsableFactor()), HttpStatus.FORBIDDEN, "NO_USABLE_FACTOR");

        var authorized = mapper.toResponse(new AuthorizeEnrollmentResult.Authorized(ENROLLMENT, "qr", EXPIRES));
        assertThat(authorized.getBody().data().status()).isEqualTo("WAITING_AUTHORIZATION");
        assertThat(authorized.getBody().data().authorizationToken()).isEqualTo("qr");
        assertFailure(mapper.toResponse(new AuthorizeEnrollmentResult.MfaPending()), HttpStatus.CONFLICT, "MFA_NOT_PASSED");
        assertFailure(mapper.toResponse(new AuthorizeEnrollmentResult.MfaFailed()), HttpStatus.UNAUTHORIZED, "MFA_FAILED");
        assertFailure(mapper.toResponse(new AuthorizeEnrollmentResult.MfaExpired()), HttpStatus.UNAUTHORIZED, "MFA_EXPIRED");
        assertFailure(mapper.toResponse(new AuthorizeEnrollmentResult.Rejected()), HttpStatus.BAD_REQUEST, "REQUEST_REJECTED");
        assertFailure(mapper.toResponse(new AuthorizeEnrollmentResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");

        var trusted = mapper.toResponse(new ClaimEnrollmentResult.Trusted("eyJ.env", EXPIRES, EXPIRES.plusSeconds(300)));
        assertThat(trusted.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(trusted.getBody().data().status()).isEqualTo("ACTIVE");
        var wrong = mapper.toResponse(new ClaimEnrollmentResult.WrongAuthorization(3));
        assertFailure(wrong, HttpStatus.UNAUTHORIZED, "WRONG_AUTHORIZATION");
        assertThat(wrong.getBody().error().details().get(0).field()).isEqualTo("attemptsLeft");
        assertThat(wrong.getBody().error().details().get(0).message()).isEqualTo("3");
        assertThat(wrong.getBody().error().message()).isEqualTo("The QR code is not correct");
        assertFailure(mapper.toResponse(new ClaimEnrollmentResult.AuthorizationExpired()), HttpStatus.UNAUTHORIZED, "AUTHORIZATION_EXPIRED");
        assertFailure(mapper.toResponse(new ClaimEnrollmentResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");
        assertFailure(mapper.toResponse(new ClaimEnrollmentResult.SessionGone()), HttpStatus.UNAUTHORIZED, "SESSION_REQUIRED");
    }

    private static void assertFailure(ResponseEntity<? extends ApiEnvelope<?>> response, HttpStatus status, String code) {
        assertThat(response.getStatusCode()).isEqualTo(status);
        assertThat(response.getBody().success()).isFalse();
        assertThat(response.getBody().error().code()).isEqualTo(code);
        assertThat(response.getBody().error().message()).isNotBlank();
    }
}
