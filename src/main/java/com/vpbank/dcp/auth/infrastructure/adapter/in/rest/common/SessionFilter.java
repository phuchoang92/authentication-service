package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.LocaleResolver;

/**
 * The token gate for {@code /api/**}: {@code /api/ns/**} (no session), {@code /internal/**} and the
 * trusted-device routes (admitted by the BFF, see {@link BffAssertionFilter}) pass through; everything
 * else needs {@code Authorization: Bearer s1:auth:session:<channel>:<sessionId>:<secret>} in the right shape,
 * handed to the controller as a request attribute. The filter reads nothing from Valkey (slice 8): each use
 * case performs the one read it needs and answers itself when the session is gone or of the wrong kind
 * (ACTIVE-only routes). A failure writes the envelope itself because filters run before controller advice.
 */
public final class SessionFilter extends OncePerRequestFilter {
    public static final String TOKEN_ATTRIBUTE = "com.vpbank.dcp.auth.session.token";
    static final String PROTECTED_PREFIX = "/api/";
    static final String OPEN_PREFIX = "/api/ns/";
    private static final String BEARER = "Bearer ";

    private final FilterFailureWriter filterFailureWriter;

    public SessionFilter(@NonNull ErrorMessages errorMessages, @NonNull LocaleResolver localeResolver) {
        this.filterFailureWriter = new FilterFailureWriter(errorMessages, localeResolver);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        boolean admittedByTheBff = path.startsWith(BffAssertionFilter.ADMITTED_PREFIX);
        return !path.startsWith(PROTECTED_PREFIX) || path.startsWith(OPEN_PREFIX) || admittedByTheBff;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<OpaqueToken> bearerToken = bearer(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (bearerToken.isEmpty()) {
            filterFailureWriter.write(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.SESSION_REQUIRED);
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
}
