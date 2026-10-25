package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.RegistrationRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.RegistrationResponse;
import com.vpbank.dcp.auth.application.command.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.result.RegisterCustomerResult;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Contract §1 wire ↔ use case. Request → command builds the value objects; result → response
 * holds the whole status/code table, so the controller decides nothing. An instance (not static)
 * because the error text comes from {@link ErrorMessages}.
 */
@RequiredArgsConstructor
public final class RegistrationRestMapper {
    @NonNull private final ErrorMessages errors;

    /** Bean Validation already checked formats; a value object that still refuses is a 400. */
    public RegisterCustomerCommand toCommand(RegistrationRequest request) {
        try {
            return RegisterCustomerCommand.builder()
                    .customerId(new CustomerId(request.customerId()))
                    .userName(new UserName(request.userName()))
                    .firstName(request.firstName())
                    .lastName(request.lastName())
                    .phoneNumber(new PhoneNumber(request.phoneNumber()))
                    .email(blank(request.email()) ? null : new Email(request.email()))
                    .build();
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<RegistrationResponse>> toResponse(RegisterCustomerResult result) {
        return switch (result) {
            case RegisterCustomerResult.Ready ready -> ResponseEntity
                    .status(ready.created() ? HttpStatus.CREATED : HttpStatus.OK)
                    .body(ApiEnvelope.success(new RegistrationResponse(ready.requestId().value(),
                            ready.customerId().value(), ready.userName().value(), "READY")));
            case RegisterCustomerResult.IdentityConflict() ->
                    errors.failure(HttpStatus.CONFLICT, ErrorCodes.IDENTITY_CONFLICT);
            case RegisterCustomerResult.ProfileIncomplete() ->
                    errors.failure(HttpStatus.CONFLICT, ErrorCodes.CUSTOMER_PROFILE_INCOMPLETE);
            case RegisterCustomerResult.Unavailable() ->
                    errors.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.ACCOUNT_CREATION_UNAVAILABLE);
        };
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
