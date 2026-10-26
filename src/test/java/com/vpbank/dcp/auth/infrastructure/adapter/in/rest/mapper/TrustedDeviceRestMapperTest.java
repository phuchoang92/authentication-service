package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ConfirmEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.InitEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ConfirmEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.InitEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class TrustedDeviceRestMapperTest {
    private static final String TOKEN = "s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000001:" + "A".repeat(43);
    private static final Instant EXPIRES = Instant.parse("2026-10-25T10:10:00Z");
    private final TrustedDeviceRestMapper mapper =
            new TrustedDeviceRestMapper(new ErrorMessages(RestConfiguration.errorMessageSource()));

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void initCommandCarriesTheJwkAsTextAndLeavesAbsentFieldsNull() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        InitEnrollmentCommand withKey = mapper.toInitCommand(TOKEN, new InitEnrollmentRequest(jwk, "IOS"));
        assertThat(withKey.devicePublicJwk()).isEqualTo("{\"kty\":\"EC\",\"crv\":\"P-256\"}");
        assertThat(withKey.platform()).isEqualTo(DevicePlatform.IOS);
        assertThat(withKey.token().value()).isEqualTo(TOKEN);

        InitEnrollmentCommand knownDevice = mapper.toInitCommand(TOKEN, new InitEnrollmentRequest(null, null));
        assertThat(knownDevice.devicePublicJwk()).isNull();
        assertThat(knownDevice.platform()).isNull();

        assertThatThrownBy(() -> mapper.toInitCommand(TOKEN, new InitEnrollmentRequest(Map.of("kty", 1), null)))
                .isInstanceOf(InvalidRequestException.class);
        assertThatThrownBy(() -> mapper.toConfirmCommand("not-a-token", new ConfirmEnrollmentRequest(jwk)))
                .isInstanceOf(InvalidRequestException.class);
        ConfirmEnrollmentCommand confirm = mapper.toConfirmCommand(TOKEN, new ConfirmEnrollmentRequest(jwk));
        assertThat(confirm.tokenEncryptionKey()).contains("\"crv\":\"P-256\"");
    }

    @Test
    void keyExchangeReturnsTheServerJwkAsAnObject() {
        InitEnrollmentResult.KeyExchange keyExchange = new InitEnrollmentResult.KeyExchange(
                EnrollmentId.random(), "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}", "eyJ.jwe", EXPIRES);
        ResponseEntity<ApiEnvelope<InitEnrollmentResponse>> response = mapper.toResponse(keyExchange);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        InitEnrollmentResponse body = response.getBody().data();
        assertThat(body.status()).isEqualTo("KEY_EXCHANGE");
        assertThat(body.enrollmentId()).isEqualTo(keyExchange.enrollmentId().value().toString());
        assertThat(body.serverPublicJwk()).containsEntry("x", "abc").containsEntry("crv", "P-256");
        assertThat(body.challenge()).isEqualTo("eyJ.jwe");
    }

    @Test
    void everyOutcomeHasItsStatusAndCode() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertFailure(mapper.toResponse(new InitEnrollmentResult.DeviceKeyRequired()), HttpStatus.BAD_REQUEST, "DEVICE_KEY_REQUIRED");
        assertFailure(mapper.toResponse(new InitEnrollmentResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");
        assertFailure(mapper.toResponse(new InitEnrollmentResult.SessionGone()), HttpStatus.UNAUTHORIZED, "SESSION_REQUIRED");
        assertFailure(mapper.toResponse(new InitEnrollmentResult.Unavailable()), HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");

        var mfaRequired = mapper.toResponse(new VerifyEnrollmentResult.MfaRequired("mfa-1", EXPIRES));
        assertThat(mfaRequired.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(mfaRequired.getBody().data().status()).isEqualTo("MFA_REQUIRED");
        assertThat(mfaRequired.getBody().data().mfaTransactionId()).isEqualTo("mfa-1");
        var wrong = mapper.toResponse(new VerifyEnrollmentResult.WrongChallenge(2));
        assertFailure(wrong, HttpStatus.UNAUTHORIZED, "WRONG_CHALLENGE");
        assertThat(wrong.getBody().error().details()).hasSize(1);
        assertThat(wrong.getBody().error().details().get(0).field()).isEqualTo("attemptsLeft");
        assertThat(wrong.getBody().error().details().get(0).message()).isEqualTo("2");
        assertThat(wrong.getBody().error().message()).isEqualTo("Device verification failed");
        assertFailure(mapper.toResponse(new VerifyEnrollmentResult.NoUsableFactor()), HttpStatus.FORBIDDEN, "NO_USABLE_FACTOR");
        assertFailure(mapper.toResponse(new VerifyEnrollmentResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");
        assertFailure(mapper.toResponse(new VerifyEnrollmentResult.SessionGone()), HttpStatus.UNAUTHORIZED, "SESSION_REQUIRED");
        assertFailure(mapper.toResponse(new VerifyEnrollmentResult.Unavailable()), HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");

        ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> trusted =
                mapper.toResponse(new ConfirmEnrollmentResult.Trusted("eyJ.env", EXPIRES, EXPIRES.plusSeconds(300)));
        assertThat(trusted.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(trusted.getBody().data().status()).isEqualTo("ACTIVE");
        assertThat(trusted.getBody().data().tokenEnvelope()).isEqualTo("eyJ.env");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.MfaPending()), HttpStatus.CONFLICT, "MFA_NOT_PASSED");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.MfaFailed()), HttpStatus.UNAUTHORIZED, "MFA_FAILED");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.MfaExpired()), HttpStatus.UNAUTHORIZED, "MFA_EXPIRED");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.Rejected()), HttpStatus.BAD_REQUEST, "REQUEST_REJECTED");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.Conflict()), HttpStatus.CONFLICT, "STATE_CONFLICT");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.SessionGone()), HttpStatus.UNAUTHORIZED, "SESSION_REQUIRED");
        assertFailure(mapper.toResponse(new ConfirmEnrollmentResult.Unavailable()), HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
    }

    private static void assertFailure(ResponseEntity<? extends ApiEnvelope<?>> response, HttpStatus status, String code) {
        assertThat(response.getStatusCode()).isEqualTo(status);
        assertThat(response.getBody().success()).isFalse();
        assertThat(response.getBody().error().code()).isEqualTo(code);
        assertThat(response.getBody().error().message()).isNotBlank();
    }
}
