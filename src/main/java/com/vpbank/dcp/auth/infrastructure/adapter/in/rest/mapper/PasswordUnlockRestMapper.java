package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorCodes;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.application.result.UnlockPasswordResult;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Unlock wire ↔ use case. */
@RequiredArgsConstructor
public final class PasswordUnlockRestMapper {
    @NonNull private final ErrorMessages errors;

    public CustomerId toCustomerId(String pathValue) {
        try {
            return new CustomerId(pathValue);
        } catch (IllegalArgumentException invalid) {
            throw new InvalidRequestException(invalid.getMessage());
        }
    }

    public ResponseEntity<ApiEnvelope<Void>> toResponse(UnlockPasswordResult result) {
        return switch (result) {
            case UnlockPasswordResult.Unlocked() -> ResponseEntity.noContent().build();
            case UnlockPasswordResult.UnknownCustomer() -> errors.failure(HttpStatus.NOT_FOUND, ErrorCodes.CUSTOMER_UNKNOWN);
            case UnlockPasswordResult.Unavailable() ->
                    errors.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
        };
    }
}
