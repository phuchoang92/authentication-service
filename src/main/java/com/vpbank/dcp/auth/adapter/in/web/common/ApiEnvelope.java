package com.vpbank.dcp.auth.adapter.in.web.common;

import java.util.List;
import java.util.Objects;

/**
 * The response body of every API: {@code {success:true, data}} or
 * {@code {success:false, error:{code, message, details}}}. The correlation ID is only in the
 * {@code X-Correlation-Id} header.
 */
public final class ApiEnvelope {
    private ApiEnvelope() {
    }

    public static <T> Success<T> success(T data) {
        return new Success<>(true, Objects.requireNonNull(data));
    }

    public static Failure failure(String code, String message, List<FieldDetail> details) {
        return new Failure(false, new Error(code, message, List.copyOf(details)));
    }

    public static Failure failure(String code, String message) {
        return failure(code, message, List.of());
    }

    public record Success<T>(boolean success, T data) { }

    public record Failure(boolean success, Error error) { }

    public record Error(String code, String message, List<FieldDetail> details) { }

    /** A field that failed validation. Never carries the submitted value. */
    public record FieldDetail(String field, String message) { }
}
