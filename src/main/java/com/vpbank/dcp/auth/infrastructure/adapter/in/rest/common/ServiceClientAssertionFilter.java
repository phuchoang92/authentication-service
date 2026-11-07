package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionVerifier.VerifiedClientAssertion;
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
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.LocaleResolver;

/**
 * The gate of the service-token route (slice 12): an internal service calls {@code POST /internal/v1/service-tokens}
 * with exactly one {@code Authorization: Bearer <client assertion>}. The filter verifies the assertion, uses its ID
 * once, and leaves the verified calling service on the request for the controller. A bad or replayed assertion is
 * {@code 401 REQUEST_REJECTED}; a replay store that cannot answer is {@code 503}, because admitting without
 * recording the use would allow a replay. The JWKS route next to it is public and not gated.
 */
public final class ServiceClientAssertionFilter extends OncePerRequestFilter {
    public static final String CALLING_SERVICE_ATTRIBUTE = "com.vpbank.dcp.auth.service-token.calling-service";
    public static final String ISSUE_PATH = "/internal/v1/service-tokens";
    private static final String BEARER = "Bearer ";

    private final ServiceClientAssertionVerifier serviceClientAssertionVerifier;
    private final AssertionReplayGuard assertionReplayGuard;
    private final FilterFailureWriter filterFailureWriter;

    public ServiceClientAssertionFilter(@NonNull ServiceClientAssertionVerifier serviceClientAssertionVerifier,
                                        @NonNull AssertionReplayGuard assertionReplayGuard,
                                        @NonNull ErrorMessages errorMessages,
                                        @NonNull LocaleResolver localeResolver) {
        this.serviceClientAssertionVerifier = serviceClientAssertionVerifier;
        this.assertionReplayGuard = assertionReplayGuard;
        this.filterFailureWriter = new FilterFailureWriter(errorMessages, localeResolver);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        boolean issueRequest = HttpMethod.POST.matches(request.getMethod()) && ISSUE_PATH.equals(request.getRequestURI());
        return !issueRequest;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<String> compactAssertion = singleBearer(request);
        if (compactAssertion.isEmpty()) {
            filterFailureWriter.write(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.REQUEST_REJECTED);
            return;
        }

        Optional<VerifiedClientAssertion> verifiedAssertion = serviceClientAssertionVerifier.verify(compactAssertion.get());
        if (verifiedAssertion.isEmpty()) {
            filterFailureWriter.write(request, response, HttpStatus.UNAUTHORIZED, ErrorCodes.REQUEST_REJECTED);
            return;
        }
        VerifiedClientAssertion assertion = verifiedAssertion.get();

        // The ID is remembered for as long as the assertion could still pass the expiry check.
        Instant rememberUntil = assertion.expiresAt().plus(ServiceClientAssertionVerifier.MAX_SKEW);
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

        request.setAttribute(CALLING_SERVICE_ATTRIBUTE, new VerifiedServiceClient(assertion.clientService()));
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
