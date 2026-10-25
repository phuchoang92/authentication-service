package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Objects;

/**
 * The response body of every API: {@code {success:true, data}} or
 * {@code {success:false, error:{code, message, details}}}. The absent half is left out of the
 * JSON. The correlation ID is only in the {@code X-Correlation-Id} header.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiEnvelope<T>(boolean success, T data, ApiError error) {

    public static <T> ApiEnvelope<T> success(T data) {
        return new ApiEnvelope<>(true, Objects.requireNonNull(data), null);
    }

    public static <T> ApiEnvelope<T> failure(String code, String message, List<FieldDetail> details) {
        return new ApiEnvelope<>(false, null, new ApiError(code, message, List.copyOf(details)));
    }

    public static <T> ApiEnvelope<T> failure(String code, String message) {
        return failure(code, message, List.of());
    }
}
