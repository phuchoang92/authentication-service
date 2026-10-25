package com.vpbank.dcp.auth.infrastructure.adapter.in.web;

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

/** Errors that never reach a controller method. Messages never echo request values. */
@RestControllerAdvice
public class ApiErrorHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ApiErrorHandler.class);
    private static final String REJECTED = "The request was rejected";

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiEnvelope.Failure> invalid(MethodArgumentNotValidException invalid) {
        List<ApiEnvelope.FieldDetail> details = invalid.getBindingResult().getFieldErrors().stream()
                .map(error -> new ApiEnvelope.FieldDetail(error.getField(), error.getDefaultMessage()))
                .sorted((a, b) -> a.field().compareTo(b.field()))
                .toList();
        return ResponseEntity.badRequest().body(ApiEnvelope.failure("REQUEST_REJECTED", REJECTED, details));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, HttpMediaTypeNotSupportedException.class})
    public ResponseEntity<ApiEnvelope.Failure> unreadable(Exception ignored) {
        return ResponseEntity.badRequest().body(ApiEnvelope.failure("REQUEST_REJECTED", REJECTED));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiEnvelope.Failure> unexpected(Exception failure) {
        LOG.error("Request failed: exceptionType={}", failure.getClass().getName());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(ApiEnvelope.failure("TEMPORARILY_UNAVAILABLE", "Please try again later"));
    }
}
