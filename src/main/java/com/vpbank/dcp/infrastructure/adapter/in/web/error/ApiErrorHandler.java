package com.vpbank.dcp.infrastructure.adapter.in.web.error;

import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.InvalidPasswordLoginRequestException;
import com.vpbank.dcp.infrastructure.adapter.in.web.session.InvalidBankingAdmissionRequestException;
import com.vpbank.dcp.core.port.out.session.SessionAuthorityUnavailableException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiErrorHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ApiErrorHandler.class);

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentNotValidException.class})
    public ResponseEntity<ApiError> malformedRequest(Exception ignored) {
        return safe(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED", "The request was rejected", ignored);
    }

    @ExceptionHandler(InvalidPasswordLoginRequestException.class)
    public ResponseEntity<ApiError> invalidPasswordRequest(InvalidPasswordLoginRequestException ignored) {
        return safe(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED", "The request was rejected", ignored);
    }

    @ExceptionHandler(InvalidBankingAdmissionRequestException.class)
    public ResponseEntity<ApiError> invalidAdmission(InvalidBankingAdmissionRequestException ignored) {
        return safe(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED", "The request was rejected", ignored);
    }

    @ExceptionHandler(SessionAuthorityUnavailableException.class)
    public ResponseEntity<ApiError> sessionUnavailable(SessionAuthorityUnavailableException ignored) {
        return safe(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE",
                "Please try again later", ignored);
    }

    @ExceptionHandler(ReplayAuthorityUnavailableException.class)
    public ResponseEntity<ApiError> authorityUnavailable(ReplayAuthorityUnavailableException ignored) {
        return safe(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE",
                "Please try again later", ignored);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> unexpectedFailure(Exception ignored) {
        return safe(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE",
                "Please try again later", ignored);
    }

    private ResponseEntity<ApiError> safe(HttpStatus status, String code, String message,
                                          Exception failure) {
        UUID correlationId = UUID.randomUUID();
        if (status.is5xxServerError()) {
            LOG.error("Authentication request failed: correlationId={} exceptionType={}",
                    correlationId, failure.getClass().getName());
        }
        ApiError body = new ApiError(code, message, correlationId);
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(body);
    }
}
