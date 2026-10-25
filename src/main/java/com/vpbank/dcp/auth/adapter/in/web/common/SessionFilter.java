package com.vpbank.dcp.auth.adapter.in.web.common;

import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.port.in.SessionSummary;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.LocaleResolver;

import java.io.IOException;
import java.util.Optional;

/**
 * The session check for {@code /api/**}: {@code /api/ns/**} (no session) and {@code /internal/**}
 * pass through; everything else needs {@code Authorization: Bearer k1.<43>} that resolves to a
 * live session, which is then available to controllers as a request attribute. Resolving never
 * touches idle time (the BFF's extend call does). A failure writes the envelope itself because
 * filters run before controller advice.
 */
@RequiredArgsConstructor
public final class SessionFilter extends OncePerRequestFilter {
    public static final String SESSION_ATTRIBUTE = "com.vpbank.dcp.auth.session";
    public static final String TOKEN_ATTRIBUTE = "com.vpbank.dcp.auth.session.token";
    static final String PROTECTED_PREFIX = "/api/";
    static final String OPEN_PREFIX = "/api/ns/";
    private static final String BEARER = "Bearer ";

    @NonNull private final CurrentSessionUseCase sessions;
    @NonNull private final ErrorMessages errors;
    /** Filters run before the DispatcherServlet sets the locale, so the filter resolves it itself. */
    @NonNull private final LocaleResolver locales;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith(PROTECTED_PREFIX) || path.startsWith(OPEN_PREFIX);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<OpaqueToken> token = bearer(request.getHeader(HttpHeaders.AUTHORIZATION));
        Optional<SessionSummary> session = token.flatMap(sessions::resolve);
        if (session.isEmpty()) {
            reject(request, response);
            return;
        }
        request.setAttribute(SESSION_ATTRIBUTE, session.get());
        request.setAttribute(TOKEN_ATTRIBUTE, token.get().value());
        chain.doFilter(request, response);
    }

    private static Optional<OpaqueToken> bearer(String header) {
        if (header == null || !header.startsWith(BEARER)) {
            return Optional.empty();
        }
        try {
            return Optional.of(new OpaqueToken(header.substring(BEARER.length()).trim()));
        } catch (IllegalArgumentException malformed) {
            return Optional.empty();
        }
    }

    private void reject(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String message = errors.message(locales.resolveLocale(request), ErrorCodes.SESSION_REQUIRED)
                .replace("\\", "\\\\").replace("\"", "\\\"");
        response.getWriter().write("{\"success\":false,\"error\":{\"code\":\"" + ErrorCodes.SESSION_REQUIRED
                + "\",\"message\":\"" + message + "\",\"details\":[]}}");
    }
}
