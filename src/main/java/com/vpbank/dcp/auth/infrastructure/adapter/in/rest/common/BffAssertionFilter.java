package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.BffAssertionVerifier.VerifiedAssertion;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant.ErrorCodes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.LocaleResolver;

/**
 * The gate for the trusted-device routes (slice 11): the BFF has checked the app's session token, its status
 * and its deadlines, and calls Auth with exactly one {@code Authorization: Bearer <BFF assertion>} naming that
 * session (DD 20 §6a). The filter verifies the assertion, uses its ID once, and leaves the admitted session on
 * the request for the controller. It reads no session. A bad or replayed assertion is {@code 401
 * REQUEST_REJECTED}; a replay store that cannot answer is {@code 503}, because admitting without recording the
 * use would allow a replay.
 */
public final class BffAssertionFilter extends OncePerRequestFilter {
    public static final String ADMISSION_ATTRIBUTE = "com.vpbank.dcp.auth.bff.admission";
    public static final String ADMITTED_PREFIX = "/api/v1/trusted-device/";
    private static final String BEARER = "Bearer ";

    private final BffAssertionVerifier bffAssertionVerifier;
    private final AssertionReplayGuard assertionReplayGuard;
    private final FilterFailureWriter filterFailureWriter;

    public BffAssertionFilter(@NonNull BffAssertionVerifier bffAssertionVerifier,
                              @NonNull AssertionReplayGuard assertionReplayGuard,
                              @NonNull ErrorMessages errorMessages,
                              @NonNull LocaleResolver localeResolver) {
        this.bffAssertionVerifier = bffAssertionVerifier;
        this.assertionReplayGuard = assertionReplayGuard;
        this.filterFailureWriter = new FilterFailureWriter(errorMessages, localeResolver);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(ADMITTED_PREFIX);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<String> compactAssertion = singleBearer(request);
        if (compactAssertion.isEmpty()) {
            filterFailureWriter.write(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.REQUEST_REJECTED);
            return;
        }

        Optional<VerifiedAssertion> verifiedAssertion = bffAssertionVerifier.verify(compactAssertion.get());
        if (verifiedAssertion.isEmpty()) {
            filterFailureWriter.write(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.REQUEST_REJECTED);
            return;
        }
        VerifiedAssertion assertion = verifiedAssertion.get();

        // The ID is remembered for as long as the assertion could still pass the expiry check.
        Instant rememberUntil = assertion.expiresAt().plus(BffAssertionVerifier.MAX_SKEW);
        boolean firstUse;
        try {
            firstUse = assertionReplayGuard.firstUse(assertion.assertionId(), rememberUntil);
        } catch (RepositoryUnavailableException failure) {
            filterFailureWriter.write(request, response, HttpStatus.SERVICE_UNAVAILABLE, ErrorCodes.TEMPORARILY_UNAVAILABLE);
            return;
        }
        if (!firstUse) {
            filterFailureWriter.write(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.REQUEST_REJECTED);
            return;
        }

        request.setAttribute(ADMISSION_ATTRIBUTE, new BffAdmission(assertion.admittedSession()));
        chain.doFilter(request, response);
    }

    /** Exactly one Authorization header, and it is a Bearer value. */
    private static Optional<String> singleBearer(HttpServletRequest request) {
        List<String> authorizationHeaders = Collections.list(request.getHeaders(HttpHeaders.AUTHORIZATION));
        if (authorizationHeaders.size() != 1) {
            return Optional.empty();
        }
        String authorizationHeader = authorizationHeaders.getFirst();
        if (!authorizationHeader.startsWith(BEARER)) {
            return Optional.empty();
        }
        return Optional.of(authorizationHeader.substring(BEARER.length()).trim());
    }
}
