package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.command.ApprovalStatusCommand;
import com.vpbank.dcp.auth.application.command.ApproveEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.AuthorizeEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.ListPendingDevicesCommand;
import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.port.in.ApprovalStatusUseCase;
import com.vpbank.dcp.auth.application.port.in.ApproveEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.AuthorizeEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.ClaimEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.ListPendingDevicesUseCase;
import com.vpbank.dcp.auth.application.port.in.RequestApprovalUseCase;
import com.vpbank.dcp.auth.application.result.ApprovalStatusResult;
import com.vpbank.dcp.auth.application.result.ApproveEnrollmentResult;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;
import com.vpbank.dcp.auth.application.result.ListPendingDevicesResult;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.SessionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ClaimEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.RequestApprovalRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.AuthorizeEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ConfirmEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.PendingDeviceResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.RequestApprovalResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.VerifyEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.DeviceApprovalRestMapper;
import jakarta.validation.Valid;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * App → Auth under {@code /api/v1/trusted-device} (slice 6, DD 20 §4 approval path). The new device calls
 * {@code request}, {@code status} and {@code claim} from its restricted session; the primary device calls
 * {@code pending}, {@code approve} and {@code authorize} from its ACTIVE session. The session filter admits
 * both kinds on this prefix; the use cases refuse the wrong kind.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class DeviceApprovalController {
    @NonNull
    private final RequestApprovalUseCase requestApprovalUseCase;
    @NonNull
    private final ApprovalStatusUseCase approvalStatusUseCase;
    @NonNull
    private final ListPendingDevicesUseCase listPendingDevicesUseCase;
    @NonNull
    private final ApproveEnrollmentUseCase approveEnrollmentUseCase;
    @NonNull
    private final AuthorizeEnrollmentUseCase authorizeEnrollmentUseCase;
    @NonNull
    private final ClaimEnrollmentUseCase claimEnrollmentUseCase;
    @NonNull
    private final DeviceApprovalRestMapper deviceApprovalRestMapper;

    @PostMapping(path = "/api/v1/trusted-device/request", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<RequestApprovalResponse>> request(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token,
            @Valid @RequestBody RequestApprovalRequest body) {
        RequestApprovalCommand command = deviceApprovalRestMapper.toRequestCommand(token, body);
        RequestApprovalResult result = requestApprovalUseCase.request(command);
        return deviceApprovalRestMapper.toResponse(result);
    }

    @GetMapping(path = "/api/v1/trusted-device/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<RequestApprovalResponse>> status(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token) {
        ApprovalStatusCommand command = deviceApprovalRestMapper.toStatusCommand(token);
        ApprovalStatusResult result = approvalStatusUseCase.status(command);
        return deviceApprovalRestMapper.toResponse(result);
    }

    @GetMapping(path = "/api/v1/trusted-device/pending", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<List<PendingDeviceResponse>>> pending(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token) {
        ListPendingDevicesCommand command = deviceApprovalRestMapper.toPendingCommand(token);
        ListPendingDevicesResult result = listPendingDevicesUseCase.pending(command);
        return deviceApprovalRestMapper.toResponse(result);
    }

    @PostMapping(path = "/api/v1/trusted-device/pending/{enrollmentId}/approve", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> approve(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token,
            @PathVariable String enrollmentId) {
        ApproveEnrollmentCommand command = deviceApprovalRestMapper.toApproveCommand(token, enrollmentId);
        ApproveEnrollmentResult result = approveEnrollmentUseCase.approve(command);
        return deviceApprovalRestMapper.toResponse(result);
    }

    @PostMapping(path = "/api/v1/trusted-device/pending/{enrollmentId}/authorize", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<AuthorizeEnrollmentResponse>> authorize(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token,
            @PathVariable String enrollmentId) {
        AuthorizeEnrollmentCommand command = deviceApprovalRestMapper.toAuthorizeCommand(token, enrollmentId);
        AuthorizeEnrollmentResult result = authorizeEnrollmentUseCase.authorize(command);
        return deviceApprovalRestMapper.toResponse(result);
    }

    @PostMapping(path = "/api/v1/trusted-device/claim", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> claim(
            @RequestAttribute(SessionFilter.TOKEN_ATTRIBUTE) String token,
            @Valid @RequestBody ClaimEnrollmentRequest body) {
        ClaimEnrollmentCommand command = deviceApprovalRestMapper.toClaimCommand(token, body);
        ClaimEnrollmentResult result = claimEnrollmentUseCase.claim(command);
        return deviceApprovalRestMapper.toResponse(result);
    }
}
