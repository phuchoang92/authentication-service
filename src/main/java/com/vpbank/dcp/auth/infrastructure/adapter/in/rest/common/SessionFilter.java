package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.LocaleResolver;

/**
 * The token gate for {@code /api/**}: {@code /api/ns/**} (no session) and {@code /internal/**} pass
 * through; everything else needs {@code Authorization: Bearer s1:auth:session:<channel>:<sessionId>:<secret>}
 * in the right shape, handed to the controller as a request attribute. The filter reads nothing from
 * Valkey (slice 8): each use case performs the one read it needs and answers itself when the session is
 * gone or of the wrong kind (ACTIVE-only or restricted-only routes). A failure writes the envelope
 * itself because filters run before controller advice.
 */
@RequiredArgsConstructor
public final class SessionFilter extends OncePerRequestFilter {
    public static final String TOKEN_ATTRIBUTE = "com.vpbank.dcp.auth.session.token";
    static final String PROTECTED_PREFIX = "/api/";
    static final String OPEN_PREFIX = "/api/ns/";
    private static final String BEARER = "Bearer ";

    @NonNull private final ErrorMessages errorMessages;
    /** Filters run before the DispatcherServlet sets the locale, so the filter resolves it itself. */
    @NonNull private final LocaleResolver localeResolver;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith(PROTECTED_PREFIX) || path.startsWith(OPEN_PREFIX);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<OpaqueToken> bearerToken = bearer(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (bearerToken.isEmpty()) {
            reject(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            return;
        }

        request.setAttribute(TOKEN_ATTRIBUTE, bearerToken.get().value());
        chain.doFilter(request, response);
    }

    private static Optional<OpaqueToken> bearer(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER)) {
            return Optional.empty();
        }
        String tokenValue = authorizationHeader.substring(BEARER.length()).trim();
        try {
            return Optional.of(new OpaqueToken(tokenValue));
        } catch (IllegalArgumentException malformed) {
            return Optional.empty();
        }
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, HttpStatus status, String code)
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
