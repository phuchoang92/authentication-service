package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.VerifiedServiceCaller;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.IssueServiceTokenRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ServiceTokenResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Service token wire ↔ use case (slice 12). */
@RequiredArgsConstructor
public final class ServiceTokenRestMapper {
    static final String TOKEN_TYPE = "Bearer";

    @NonNull private final ErrorMessages errorMessages;

    public IssueServiceTokenCommand toCommand(VerifiedServiceCaller caller, IssueServiceTokenRequest request) {
        ServiceScope scope = ServiceScope.fromCode(request.scope())
                .orElseThrow(() -> new InvalidRequestException("scope is not a known scope"));
        BusinessReference businessReference = request.businessReference() == null || request.businessReference().isEmpty()
                ? null : new BusinessReference(request.businessReference());
        return new IssueServiceTokenCommand(caller.caller(), scope, businessReference);
    }

    public ResponseEntity<ApiEnvelope<ServiceTokenResponse>> toResponse(IssueServiceTokenResult result) {
        return switch (result) {
            case IssueServiceTokenResult.Issued issued -> issued(issued);
            case IssueServiceTokenResult.ScopeNotAllowed() ->
                    errorMessages.failure(HttpStatus.FORBIDDEN, ErrorCodes.SCOPE_NOT_ALLOWED);
            case IssueServiceTokenResult.BusinessReferenceRequired() ->
                    errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
        };
    }

    private static ResponseEntity<ApiEnvelope<ServiceTokenResponse>> issued(IssueServiceTokenResult.Issued issued) {
        ServiceTokenResponse response = new ServiceTokenResponse(
                issued.token(),
                TOKEN_TYPE,
                issued.scope().code(),
                issued.expiresAt());
        return ResponseEntity.ok(ApiEnvelope.success(response));
    }
}
