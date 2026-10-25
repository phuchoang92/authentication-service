package com.vpbank.dcp.infrastructure.adapter.in.web.security;

import com.vpbank.dcp.core.security.DpopExpectation;
import com.vpbank.dcp.core.security.DpopProofDecoder;
import com.vpbank.dcp.core.security.InvalidDpopProofException;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.constant.DpopRequestAttributes;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.util.Collections;
import java.util.Objects;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/** Verifies App proof after workload authorization, before JSON binding or the login use case. */
public final class DpopProofFilter extends OncePerRequestFilter {
    private final RequestMatcher password = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/internal/v1/authentications/password");
    private final DpopProofDecoder decoder;
    private final URI publicUri;
    private final Clock clock;
    private final SecurityErrorResponse errors;

    public DpopProofFilter(DpopProofDecoder decoder, ExternalUriPolicy externalUris,
                           Clock clock, SecurityErrorResponse errors) {
        this.decoder = Objects.requireNonNull(decoder, "decoder");
        this.publicUri = Objects.requireNonNull(externalUris, "externalUris")
                .forPath("/api/v1/authentications/password");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.errors = Objects.requireNonNull(errors, "errors");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !password.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        var proofs = Collections.list(request.getHeaders("DPoP"));
        if (proofs.size() != 1 || proofs.getFirst().length() < 64
                || proofs.getFirst().length() > 4096 || proofs.getFirst().isBlank()) {
            errors.reject(response, HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        try {
            // Always derive htu from trusted server configuration, never forwarded headers.
            request.setAttribute(DpopRequestAttributes.VERIFIED_DPOP_PROOF, decoder.verify(proofs.getFirst(),
                    DpopExpectation.forInitial(request.getMethod(), publicUri, clock.instant())));
        } catch (InvalidDpopProofException invalid) {
            errors.reject(response, HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(request, response);
    }
}
