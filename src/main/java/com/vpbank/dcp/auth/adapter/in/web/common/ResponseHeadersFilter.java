package com.vpbank.dcp.auth.adapter.in.web.common;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Every response, success or error, gets a fresh {@code X-Correlation-Id} and
 * {@code Cache-Control: no-store}. Auth generates the ID; the caller keeps it to report errors.
 */
public final class ResponseHeadersFilter extends OncePerRequestFilter {
    public static final String CORRELATION_ID = "X-Correlation-Id";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String correlationId = UUID.randomUUID().toString();
        request.setAttribute(CORRELATION_ID, correlationId);
        response.setHeader(CORRELATION_ID, correlationId);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        chain.doFilter(request, response);
    }
}
