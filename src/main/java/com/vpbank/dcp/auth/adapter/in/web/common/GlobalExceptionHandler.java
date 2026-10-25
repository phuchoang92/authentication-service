package com.vpbank.dcp.auth.adapter.in.web.common;

import com.vpbank.dcp.auth.domain.exception.RegistrationStateException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/** Errors that never reach a web mapper. Messages are localized; they never echo request values. */
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {
    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @NonNull private final ErrorMessages errors;

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiEnvelope<Void>> invalid(MethodArgumentNotValidException invalid) {
        List<FieldDetail> details = invalid.getBindingResult().getFieldErrors().stream()
                .map(error -> new FieldDetail(error.getField(), error.getDefaultMessage()))
                .sorted((a, b) -> a.field().compareTo(b.field()))
                .toList();
        return errors.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED, details);
    }

    /** A value object refused what Bean Validation let through; the rule name is not user text. */
    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<ApiEnvelope<Void>> invalidValue(InvalidRequestException invalid) {
        LOG.info("Request rejected by a value object: {}", invalid.getMessage());
        return errors.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, HttpMediaTypeNotSupportedException.class})
    public ResponseEntity<ApiEnvelope<Void>> unreadable(Exception ignored) {
        return errors.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
    }

    /** A domain state machine was driven out of order: a bug, not an outage. */
    @ExceptionHandler(RegistrationStateException.class)
    public ResponseEntity<ApiEnvelope<Void>> bug(RegistrationStateException failure) {
        LOG.error("Illegal state transition: {}", failure.getMessage());
        return errors.failure(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiEnvelope<Void>> unexpected(Exception failure) {
        LOG.error("Request failed: exceptionType={}", failure.getClass().getName());
        return errors.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
    }
}
