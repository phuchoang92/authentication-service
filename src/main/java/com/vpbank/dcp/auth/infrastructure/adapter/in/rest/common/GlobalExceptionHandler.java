package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.domain.exception.RegistrationStateException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import java.util.Comparator;
import java.util.List;
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

/** Errors that never reach a web mapper. Messages are localized; they never echo request values. */
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {
    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @NonNull private final ErrorMessages errorMessages;

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiEnvelope<Void>> invalid(MethodArgumentNotValidException invalid) {
        List<FieldDetail> fieldDetails = invalid.getBindingResult().getFieldErrors().stream()
                .map(fieldError -> new FieldDetail(fieldError.getField(), fieldError.getDefaultMessage()))
                .sorted(Comparator.comparing(FieldDetail::field))
                .toList();
        return errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED, fieldDetails);
    }

    /** A value object refused what Bean Validation let through; the rule name is not user text. */
    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<ApiEnvelope<Void>> invalidValue(InvalidRequestException invalid) {
        LOG.info("Request rejected by a value object: {}", invalid.getMessage());
        return errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, HttpMediaTypeNotSupportedException.class})
    public ResponseEntity<ApiEnvelope<Void>> unreadable(Exception ignored) {
        return errorMessages.failure(HttpStatus.BAD_REQUEST, ErrorCodes.REQUEST_REJECTED);
    }

    /** A domain state machine was driven out of order: a bug, not an outage. */
    @ExceptionHandler(RegistrationStateException.class)
    public ResponseEntity<ApiEnvelope<Void>> bug(RegistrationStateException failure) {
        LOG.error("Illegal state transition: {}", failure.getMessage());
        return errorMessages.failure(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiEnvelope<Void>> unexpected(Exception failure) {
        LOG.error("Request failed: exceptionType={}", failure.getClass().getName());
        return errorMessages.failure(HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
    }
}
