package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Locale;

/**
 * User-facing error text, resolved from {@code messages/errors_<lang>} for the request's locale
 * (the Accept-Language header, see RestConfiguration). The code is the message key, so the
 * properties files are the error catalogue. Arguments are never values the customer typed.
 */
@RequiredArgsConstructor
public final class ErrorMessages {
    @NonNull private final MessageSource messages;

    public String message(String code, Object... args) {
        return message(LocaleContextHolder.getLocale(), code, args);
    }

    /** For filters, which run before Spring MVC has resolved the request locale. */
    public String message(Locale locale, String code, Object... args) {
        return messages.getMessage(code, args, locale);
    }

    public <T> ResponseEntity<ApiEnvelope<T>> failure(HttpStatus status, String code, Object... args) {
        return ResponseEntity.status(status).body(ApiEnvelope.failure(code, message(code, args)));
    }

    public <T> ResponseEntity<ApiEnvelope<T>> failure(HttpStatus status, String code, List<FieldDetail> details) {
        return ResponseEntity.status(status).body(ApiEnvelope.failure(code, message(code), details));
    }
}
