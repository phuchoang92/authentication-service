package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.LocaleResolver;

/**
 * Writes the failure envelope from a servlet filter. Filters run before controller advice and before the
 * DispatcherServlet sets the locale, so the language is resolved here from the request itself.
 */
@RequiredArgsConstructor
public final class FilterFailureWriter {
    @NonNull private final ErrorMessages errorMessages;
    @NonNull private final LocaleResolver localeResolver;

    public void write(HttpServletRequest request, HttpServletResponse response, HttpStatus status, String code)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Locale requestLocale = localeResolver.resolveLocale(request);
        String message = errorMessages.message(requestLocale, code);
        String jsonSafeMessage = message
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");

        String failureEnvelope = "{\"success\":false,\"error\":{\"code\":\"" + code
                + "\",\"message\":\"" + jsonSafeMessage + "\",\"details\":[]}}";
        response.getWriter().write(failureEnvelope);
    }
}
