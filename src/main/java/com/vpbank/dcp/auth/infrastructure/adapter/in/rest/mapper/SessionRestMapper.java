package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.ExtendSessionRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ExtendSessionResponse;
import com.vpbank.dcp.auth.application.command.ExtendSessionCommand;
import com.vpbank.dcp.auth.application.result.ExtendSessionResult;
import com.vpbank.dcp.auth.application.command.LogoutCommand;
import com.vpbank.dcp.auth.application.result.LogoutResult;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Logout and extend wire ↔ use cases. */
@RequiredArgsConstructor
public final class SessionRestMapper {
    @NonNull private final ErrorMessages errors;

    public ExtendSessionCommand toCommand(ExtendSessionRequest request) {
        return ExtendSessionCommand.builder()
                .lookupKeyVersion(request.sessionLookup().lookupKeyVersion())
                .lookupDigest(request.sessionLookup().lookupDigest())
                .admittedAt(request.admittedAt())
                .routeId(request.routeId())
                .admissionId(request.admissionId())
                .build();
    }

    /** The filter already validated the token's shape; it is handed on as text to keep controllers free of domain types. */
    public LogoutCommand toLogoutCommand(String token) {
        return new LogoutCommand(new OpaqueToken(token));
    }

    public ResponseEntity<ApiEnvelope<ExtendSessionResponse>> toResponse(ExtendSessionResult result) {
        return switch (result) {
            case ExtendSessionResult.Extended ok -> ResponseEntity.ok(ApiEnvelope.success(
                    new ExtendSessionResponse(ok.idleExpiresAt(), ok.absoluteExpiresAt())));
            case ExtendSessionResult.Rejected() -> errors.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
            case ExtendSessionResult.Gone() -> errors.failure(HttpStatus.GONE, ErrorCodes.SESSION_GONE);
            case ExtendSessionResult.Conflict() -> errors.failure(HttpStatus.CONFLICT, ErrorCodes.SESSION_CONFLICT);
            case ExtendSessionResult.Unavailable() ->
                    errors.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }

    public ResponseEntity<ApiEnvelope<Void>> toResponse(LogoutResult result) {
        return switch (result) {
            case LogoutResult.Ended() -> ResponseEntity.noContent().build();
            case LogoutResult.Unavailable() ->
                    errors.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }
}
