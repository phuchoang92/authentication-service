package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.ApprovalStatusCommand;
import com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.AuthorizeEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
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
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.FieldDetail;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.JwkJson;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ClaimEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.RequestApprovalRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.AuthorizeEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ConfirmEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.PendingDeviceResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.RequestApprovalResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.VerifyEnrollmentResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Approval of a new device by the primary device, wire ↔ use cases (slice 6). The session token arrives as
 * text from the session filter; the enrollment ID is an opaque string on the wire (CODE_CONVENTIONS §5) and a
 * typed ID inside. The status/code table lives here, so the controller decides nothing.
 */
@RequiredArgsConstructor
public final class DeviceApprovalRestMapper {
    /** The detail field that tells the new device how many wrong tokens are left before the request fails. */
    static final String ATTEMPTS_LEFT = "attemptsLeft";

    @NonNull private final ErrorMessages errorMessages;

    // ---- requests → commands ----

    public RequestApprovalCommand toRequestCommand(String token, RequestApprovalRequest request) {
        try {
            // Both are optional: a known installation keeps the key and platform Auth already stores.
            String devicePublicJwk = request.devicePublicJwk() == null ? null : JwkJson.toJson(request.devicePublicJwk());
            DevicePlatform platform = request.platform() == null ? null : DevicePlatform.valueOf(request.platform());

            return new RequestApprovalCommand(new OpaqueToken(token), devicePublicJwk, platform);
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ApprovalStatusCommand toStatusCommand(String token) {
        try {
            return new ApprovalStatusCommand(new OpaqueToken(token));
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ListPendingDevicesCommand toPendingCommand(String token) {
        try {
            return new ListPendingDevicesCommand(new OpaqueToken(token));
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ApproveEnrollmentCommand toApproveCommand(String token, String enrollmentId) {
        try {
            return new ApproveEnrollmentCommand(new OpaqueToken(token), toEnrollmentId(enrollmentId));
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public AuthorizeEnrollmentCommand toAuthorizeCommand(String token, String enrollmentId) {
        try {
            return new AuthorizeEnrollmentCommand(new OpaqueToken(token), toEnrollmentId(enrollmentId));
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ClaimEnrollmentCommand toClaimCommand(String token, ClaimEnrollmentRequest request) {
        try {
            String tokenEncryptionKey = JwkJson.toJson(request.tokenEncryptionKey());
            return new ClaimEnrollmentCommand(new OpaqueToken(token), request.authorizationToken(), tokenEncryptionKey);
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    /** The public ID is the UUID text Auth issued; anything else is a 400, never a lookup. */
    private static EnrollmentId toEnrollmentId(String publicEnrollmentId) {
        return new EnrollmentId(UUID.fromString(publicEnrollmentId));
    }

    // ---- results → responses ----

    public ResponseEntity<ApiEnvelope<RequestApprovalResponse>> toResponse(RequestApprovalResult result) {
        return switch (result) {
            case RequestApprovalResult.WaitingApproval waiting -> waiting(waiting);
            case RequestApprovalResult.DeviceKeyRequired() ->
                    errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.DEVICE_KEY_REQUIRED);
            case RequestApprovalResult.TooManyPending() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.TOO_MANY_PENDING_DEVICES);
            case RequestApprovalResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case RequestApprovalResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case RequestApprovalResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<RequestApprovalResponse>> toResponse(ApprovalStatusResult result) {
        return switch (result) {
            case ApprovalStatusResult.Status status -> status(status);
            case ApprovalStatusResult.NoRequest() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case ApprovalStatusResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case ApprovalStatusResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<List<PendingDeviceResponse>>> toResponse(ListPendingDevicesResult result) {
        return switch (result) {
            case ListPendingDevicesResult.Pending pending -> pending(pending);
            case ListPendingDevicesResult.NotPrimaryDevice() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.NOT_PRIMARY_DEVICE);
            case ListPendingDevicesResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case ListPendingDevicesResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> toResponse(ApproveEnrollmentResult result) {
        return switch (result) {
            case ApproveEnrollmentResult.MfaRequired mfaRequired -> mfaRequired(mfaRequired);
            case ApproveEnrollmentResult.NotPrimaryDevice() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.NOT_PRIMARY_DEVICE);
            case ApproveEnrollmentResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case ApproveEnrollmentResult.NoUsableFactor() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.NO_USABLE_FACTOR);
            case ApproveEnrollmentResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case ApproveEnrollmentResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<AuthorizeEnrollmentResponse>> toResponse(AuthorizeEnrollmentResult result) {
        return switch (result) {
            case AuthorizeEnrollmentResult.Authorized authorized -> authorized(authorized);
            case AuthorizeEnrollmentResult.MfaPending() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.MFA_NOT_PASSED);
            case AuthorizeEnrollmentResult.MfaFailed() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.MFA_FAILED);
            case AuthorizeEnrollmentResult.MfaExpired() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.MFA_EXPIRED);
            case AuthorizeEnrollmentResult.Rejected() ->
                    errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
            case AuthorizeEnrollmentResult.NotPrimaryDevice() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.NOT_PRIMARY_DEVICE);
            case AuthorizeEnrollmentResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case AuthorizeEnrollmentResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case AuthorizeEnrollmentResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> toResponse(ClaimEnrollmentResult result) {
        return switch (result) {
            case ClaimEnrollmentResult.Trusted trusted -> trusted(trusted);
            case ClaimEnrollmentResult.WrongAuthorization wrongAuthorization -> wrongAuthorization(wrongAuthorization);
            case ClaimEnrollmentResult.AuthorizationExpired() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.AUTHORIZATION_EXPIRED);
            case ClaimEnrollmentResult.Conflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.STATE_CONFLICT);
            case ClaimEnrollmentResult.SessionGone() ->
                    errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            case ClaimEnrollmentResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    private static ResponseEntity<ApiEnvelope<RequestApprovalResponse>> waiting(RequestApprovalResult.WaitingApproval waiting) {
        RequestApprovalResponse response = new RequestApprovalResponse(
                EnrollmentState.WAITING_APPROVAL.name(),
                publicId(waiting.enrollmentId()),
                waiting.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }

    private static ResponseEntity<ApiEnvelope<RequestApprovalResponse>> status(ApprovalStatusResult.Status status) {
        RequestApprovalResponse response = new RequestApprovalResponse(
                status.state().name(),
                publicId(status.enrollmentId()),
                status.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }

    private static ResponseEntity<ApiEnvelope<List<PendingDeviceResponse>>> pending(ListPendingDevicesResult.Pending pending) {
        List<PendingDeviceResponse> responses = new ArrayList<>();
        for (PendingDeviceSummary summary : pending.devices()) {
            PendingDeviceResponse response = new PendingDeviceResponse(
                    publicId(summary.enrollmentId()),
                    DeviceRestMapper.mask(summary.deviceId().value()),
                    summary.platform().name(),
                    summary.state().name(),
                    summary.expiresAt());
            responses.add(response);
        }
        return ResponseEntity.ok(ApiEnvelope.success(responses));
    }

    private static ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> mfaRequired(ApproveEnrollmentResult.MfaRequired mfaRequired) {
        VerifyEnrollmentResponse response = new VerifyEnrollmentResponse(
                EnrollmentState.MFA_REQUIRED.name(),
                mfaRequired.mfaTransactionId(),
                mfaRequired.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }

    private static ResponseEntity<ApiEnvelope<AuthorizeEnrollmentResponse>> authorized(AuthorizeEnrollmentResult.Authorized authorized) {
        AuthorizeEnrollmentResponse response = new AuthorizeEnrollmentResponse(
                EnrollmentState.WAITING_AUTHORIZATION.name(),
                publicId(authorized.enrollmentId()),
                authorized.authorizationToken(),
                authorized.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }

    /** 201: the new device is trusted and primary; its ACTIVE session token is inside the envelope. */
    private static ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> trusted(ClaimEnrollmentResult.Trusted trusted) {
        ConfirmEnrollmentResponse response = new ConfirmEnrollmentResponse(
                trusted.tokenEnvelope(),
                SessionStatus.ACTIVE.name(),
                trusted.idleExpiresAt(),
                trusted.absoluteExpiresAt());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiEnvelope.success(response));
    }

    /** 401 with the remaining attempts as a detail; 0 means the request failed and the session is gone. */
    private ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> wrongAuthorization(
            ClaimEnrollmentResult.WrongAuthorization wrongAuthorization) {
        FieldDetail attemptsLeft = new FieldDetail(ATTEMPTS_LEFT, Integer.toString(wrongAuthorization.attemptsLeft()));
        return errorMessages.failure(HttpStatus.UNAUTHORIZED, ErrorCodes.WRONG_AUTHORIZATION, List.of(attemptsLeft));
    }

    /** The public form of an enrollment ID: the UUID text Auth issued (CODE_CONVENTIONS §5). */
    private static String publicId(EnrollmentId enrollmentId) {
        return enrollmentId.value().toString();
    }
}
