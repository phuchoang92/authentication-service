package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.VerifyEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.EnrollmentState;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.FieldDetail;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.JwkJson;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ConfirmEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.InitEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.VerifyEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ConfirmEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.InitEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.VerifyEnrollmentResponse;
import java.util.List;
import java.util.Map;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Trusted-device enrollment wire ↔ use cases (DD 20 §4, slice 5). The restricted token arrives as
 * text from the session filter; JWKs cross as JSON objects. The status/code table lives here, so
 * the controller decides nothing.
 */
@RequiredArgsConstructor
public final class TrustedDeviceRestMapper {
    /** The detail field that tells the app how many wrong answers are left before the enrollment fails. */
    static final String ATTEMPTS_LEFT = "attemptsLeft";

    @NonNull private final ErrorMessages errorMessages;

    public InitEnrollmentCommand toInitCommand(String token, InitEnrollmentRequest request) {
        try {
            // Both are optional: a known device keeps the key and platform Auth already stores.
            String devicePublicJwk = request.devicePublicJwk() == null ? null : JwkJson.toJson(request.devicePublicJwk());
            DevicePlatform platform = request.platform() == null ? null : DevicePlatform.valueOf(request.platform());

            return new InitEnrollmentCommand(new OpaqueToken(token), devicePublicJwk, platform);
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public VerifyEnrollmentCommand toVerifyCommand(String token, VerifyEnrollmentRequest request) {
        try {
            return new VerifyEnrollmentCommand(new OpaqueToken(token), request.challengeResponse());
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ConfirmEnrollmentCommand toConfirmCommand(String token, ConfirmEnrollmentRequest request) {
        try {
            String tokenEncryptionKey = JwkJson.toJson(request.tokenEncryptionKey());
            return new ConfirmEnrollmentCommand(new OpaqueToken(token), tokenEncryptionKey);
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<InitEnrollmentResponse>> toResponse(InitEnrollmentResult result) {
        return switch (result) {
            case InitEnrollmentResult.KeyExchange keyExchange -> keyExchange(keyExchange);
            case InitEnrollmentResult.DeviceKeyRequired() ->
                    errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.DEVICE_KEY_REQUIRED);
            case InitEnrollmentResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case InitEnrollmentResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case InitEnrollmentResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> toResponse(VerifyEnrollmentResult result) {
        return switch (result) {
            case VerifyEnrollmentResult.MfaRequired mfaRequired -> mfaRequired(mfaRequired);
            case VerifyEnrollmentResult.WrongChallenge wrongChallenge -> wrongChallenge(wrongChallenge);
            case VerifyEnrollmentResult.NoUsableFactor() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.NO_USABLE_FACTOR);
            case VerifyEnrollmentResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case VerifyEnrollmentResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case VerifyEnrollmentResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> toResponse(ConfirmEnrollmentResult result) {
        return switch (result) {
            case ConfirmEnrollmentResult.Trusted trusted -> trusted(trusted);
            case ConfirmEnrollmentResult.MfaPending() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.MFA_NOT_PASSED);
            case ConfirmEnrollmentResult.MfaFailed() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.MFA_FAILED);
            case ConfirmEnrollmentResult.MfaExpired() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.MFA_EXPIRED);
            case ConfirmEnrollmentResult.Rejected() ->
                    errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
            case ConfirmEnrollmentResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case ConfirmEnrollmentResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case ConfirmEnrollmentResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    private static ResponseEntity<ApiEnvelope<InitEnrollmentResponse>> keyExchange(
            InitEnrollmentResult.KeyExchange keyExchange) {
        Map<String, Object> serverPublicJwk = JwkJson.toMap(keyExchange.serverPublicJwk());
        InitEnrollmentResponse response = new InitEnrollmentResponse(
                EnrollmentState.KEY_EXCHANGE.name(),
                keyExchange.enrollmentId().value(),
                serverPublicJwk,
                keyExchange.challenge(),
                keyExchange.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }

    private static ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> mfaRequired(
            VerifyEnrollmentResult.MfaRequired mfaRequired) {
        VerifyEnrollmentResponse response = new VerifyEnrollmentResponse(
                EnrollmentState.MFA_REQUIRED.name(),
                mfaRequired.mfaTransactionId(),
                mfaRequired.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }

    /** 401 with the remaining attempts as a detail; 0 means the enrollment failed and the session is gone. */
    private ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> wrongChallenge(
            VerifyEnrollmentResult.WrongChallenge wrongChallenge) {
        FieldDetail attemptsLeft = new FieldDetail(ATTEMPTS_LEFT, Integer.toString(wrongChallenge.attemptsLeft()));
        return errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.WRONG_CHALLENGE, List.of(attemptsLeft));
    }

    /** 201: a full ACTIVE session was created for the now trusted device. */
    private static ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> trusted(ConfirmEnrollmentResult.Trusted trusted) {
        ConfirmEnrollmentResponse response = new ConfirmEnrollmentResponse(
                trusted.tokenEnvelope(),
                SessionStatus.ACTIVE.name(),
                trusted.idleExpiresAt(),
                trusted.absoluteExpiresAt());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiEnvelope.success(response));
    }
}
