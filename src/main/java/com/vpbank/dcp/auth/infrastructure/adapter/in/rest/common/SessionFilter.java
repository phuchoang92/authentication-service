package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.application.port.in.CurrentSessionUseCase;
import com.vpbank.dcp.auth.application.result.SessionSummary;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
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
 * The session check for {@code /api/**}: {@code /api/ns/**} (no session) and {@code /internal/**}
 * pass through; everything else needs {@code Authorization: Bearer s1:auth:session:<channel>:<sessionId>:<secret>} that resolves to a
 * live session, which is then available to controllers as a request attribute. A restricted
 * NEED_TRUSTED_DEVICE session may only log out or call the trusted-device routes (DD 20 §3);
 * anything else is 403 DEVICE_TRUST_REQUIRED. Resolving never touches idle time (the BFF's extend
 * call does). A failure writes the envelope itself because filters run before controller advice.
 */
@RequiredArgsConstructor
public final class SessionFilter extends OncePerRequestFilter {
    public static final String SESSION_ATTRIBUTE = "com.vpbank.dcp.auth.session";
    public static final String TOKEN_ATTRIBUTE = "com.vpbank.dcp.auth.session.token";
    static final String PROTECTED_PREFIX = "/api/";
    static final String OPEN_PREFIX = "/api/ns/";
    /** What a restricted session may still reach: an exact path, or every path under a trailing slash. */
    static final List<String> RESTRICTED_ALLOWED = List.of("/api/v1/logout", "/api/v1/trusted-device/");
    private static final String BEARER = "Bearer ";

    @NonNull private final CurrentSessionUseCase currentSessionUseCase;
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
        Optional<SessionSummary> liveSession = bearerToken.flatMap(currentSessionUseCase::resolve);
        if (liveSession.isEmpty()) {
            reject(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
            return;
        }
        SessionSummary session = liveSession.get();

        boolean restricted = session.status() != SessionStatus.ACTIVE;
        if (restricted && !restrictedAllowed(request.getRequestURI())) {
            reject(request, response, HttpStatus.FORBIDDEN, ErrorCodes.DEVICE_TRUST_REQUIRED);
            return;
        }

        request.setAttribute(SESSION_ATTRIBUTE, session);
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

    private static boolean restrictedAllowed(String path) {
        for (String allowed : RESTRICTED_ALLOWED) {
            boolean allowsWholePrefix = allowed.endsWith("/");
            if (allowsWholePrefix && path.startsWith(allowed)) {
                return true;
            }
            if (!allowsWholePrefix && path.equals(allowed)) {
                return true;
            }
        }
        return false;
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
