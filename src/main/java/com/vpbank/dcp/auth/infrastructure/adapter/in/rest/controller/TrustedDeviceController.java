package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.command.VerifyEnrollmentCommand;
import com.vpbank.dcp.auth.application.port.in.ConfirmEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.InitEnrollmentUseCase;
import com.vpbank.dcp.auth.application.port.in.VerifyEnrollmentUseCase;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.BffAdmission;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.BffAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ConfirmEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.InitEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.VerifyEnrollmentRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ConfirmEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.InitEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.VerifyEnrollmentResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.TrustedDeviceRestMapper;
import jakarta.validation.Valid;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * App → Auth from a restricted NEED_TRUSTED_DEVICE session ({@code /api}, DD 20 §4): init → verify →
 * confirm. The BFF admits the session ({@link BffAssertionFilter}); an ACTIVE one reaches the use case and
 * is answered 409 STATE_CONFLICT.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.login", name = "enabled", havingValue = "true")
@RequiredArgsConstructor
public class TrustedDeviceController {
    @NonNull
    private final InitEnrollmentUseCase initEnrollmentUseCase;
    @NonNull
    private final VerifyEnrollmentUseCase verifyEnrollmentUseCase;
    @NonNull
    private final ConfirmEnrollmentUseCase confirmEnrollmentUseCase;
    @NonNull
    private final TrustedDeviceRestMapper trustedDeviceRestMapper;

    @PostMapping(path = "/api/v1/trusted-device/init", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<InitEnrollmentResponse>> init(
            @RequestAttribute(BffAssertionFilter.ADMISSION_ATTRIBUTE) BffAdmission admission,
            @Valid @RequestBody InitEnrollmentRequest body) {
        InitEnrollmentCommand command = trustedDeviceRestMapper.toInitCommand(admission, body);
        InitEnrollmentResult result = initEnrollmentUseCase.init(command);
        return trustedDeviceRestMapper.toResponse(result);
    }

    @PostMapping(path = "/api/v1/trusted-device/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<VerifyEnrollmentResponse>> verify(
            @RequestAttribute(BffAssertionFilter.ADMISSION_ATTRIBUTE) BffAdmission admission,
            @Valid @RequestBody VerifyEnrollmentRequest body) {
        VerifyEnrollmentCommand command = trustedDeviceRestMapper.toVerifyCommand(admission, body);
        VerifyEnrollmentResult result = verifyEnrollmentUseCase.verify(command);
        return trustedDeviceRestMapper.toResponse(result);
    }

    @PostMapping(path = "/api/v1/trusted-device/confirm", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiEnvelope<ConfirmEnrollmentResponse>> confirm(
            @RequestAttribute(BffAssertionFilter.ADMISSION_ATTRIBUTE) BffAdmission admission,
            @Valid @RequestBody ConfirmEnrollmentRequest body) {
        ConfirmEnrollmentCommand command = trustedDeviceRestMapper.toConfirmCommand(admission, body);
        ConfirmEnrollmentResult result = confirmEnrollmentUseCase.confirm(command);
        return trustedDeviceRestMapper.toResponse(result);
    }
}
