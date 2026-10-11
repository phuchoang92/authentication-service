package com.vpbank.dcp.infrastructure.adapter.in.web;

import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * TLS authenticates the certificate; this filter authorizes its exact workload URI SAN.
 */
public final class WorkloadIdentityFilter extends OncePerRequestFilter {

    private final Set<String> allowedWorkloadUris;
    private final JsonMapper json;

    public WorkloadIdentityFilter(Set<String> allowedWorkloadUris, JsonMapper json) {
        this.allowedWorkloadUris = Set.copyOf(Objects.requireNonNull(allowedWorkloadUris));
        this.json = Objects.requireNonNull(json, "json");
        if (this.allowedWorkloadUris.isEmpty()) {
            throw new InvalidWorkloadIdentityConfigurationException();
        }
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!request.isSecure() || !hasAllowedCertificate(request)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Cache-Control", "no-store");
            json.writeValue(response.getOutputStream(), new ApiError(
                    "REQUEST_REJECTED", "The request was rejected", UUID.randomUUID()));
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean hasAllowedCertificate(HttpServletRequest request) {
        Object presented = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!(presented instanceof X509Certificate[] chain) || chain.length == 0) {
            return false;
        }
        try {
            chain[0].checkValidity();
            Collection<List<?>> names = chain[0].getSubjectAlternativeNames();
            if (names == null) {
                return false;
            }
            return names.stream().anyMatch(name -> name.size() >= 2
                    && Integer.valueOf(6).equals(name.get(0))
                    && allowedWorkloadUris.contains(name.get(1)));
        } catch (CertificateParsingException | java.security.cert.CertificateExpiredException
                 | java.security.cert.CertificateNotYetValidException failure) {
            return false;
        }
    }
}
