package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.application.command.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.result.RegisterCustomerResult;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.RegistrationRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.RegistrationResponse;
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
    /** The only state the API reports for a finished registration. */
    private static final String STATE_READY = "READY";

    @NonNull private final ErrorMessages errorMessages;

    /** Bean Validation already checked formats; a value object that still refuses is a 400. */
    public RegisterCustomerCommand toCommand(RegistrationRequest request) {
        try {
            Email email = blank(request.email()) ? null : new Email(request.email());
            return RegisterCustomerCommand.builder()
                    .customerId(new CustomerId(request.customerId()))
                    .userName(new UserName(request.userName()))
                    .firstName(request.firstName())
                    .lastName(request.lastName())
                    .phoneNumber(new PhoneNumber(request.phoneNumber()))
                    .email(email)
                    .build();
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<RegistrationResponse>> toResponse(RegisterCustomerResult result) {
        return switch (result) {
            case RegisterCustomerResult.Ready ready -> ready(ready);
            case RegisterCustomerResult.IdentityConflict() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.IDENTITY_CONFLICT);
            case RegisterCustomerResult.ProfileIncomplete() ->
                    errorMessages.failure(HttpStatus.CONFLICT, ErrorCodes.CUSTOMER_PROFILE_INCOMPLETE);
            case RegisterCustomerResult.Unavailable() ->
                    errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.ACCOUNT_CREATION_UNAVAILABLE);
        };
    }

    /** 201 when this call created the account, 200 when an identical earlier request already had. */
    private static ResponseEntity<ApiEnvelope<RegistrationResponse>> ready(RegisterCustomerResult.Ready ready) {
        HttpStatus status = ready.created() ? HttpStatus.CREATED : HttpStatus.OK;
        RegistrationResponse response = new RegistrationResponse(
                ready.requestId().value(),
                ready.customerId().value(),
                ready.userName().value(),
                STATE_READY);
        return ResponseEntity.status(status).body(ApiEnvelope.success(response));
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
