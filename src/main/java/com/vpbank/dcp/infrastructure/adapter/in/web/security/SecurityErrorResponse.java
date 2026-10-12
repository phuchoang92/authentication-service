package com.vpbank.dcp.infrastructure.adapter.in.web.security;

import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiError;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import tools.jackson.databind.json.JsonMapper;

/** Filter failures use the same safe JSON contract as the HTTP boundary. */
public final class SecurityErrorResponse implements AuthenticationEntryPoint, AccessDeniedHandler {
    private final JsonMapper json;

    public SecurityErrorResponse(JsonMapper json) {
        this.json = Objects.requireNonNull(json, "json");
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException failure) throws IOException {
        reject(response, HttpServletResponse.SC_FORBIDDEN);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException failure) throws IOException {
        reject(response, HttpServletResponse.SC_FORBIDDEN);
    }

    public void reject(HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        Object body = status == HttpServletResponse.SC_UNAUTHORIZED
                ? new PasswordLoginErrorResponse("REQUEST_REJECTED", "The request was rejected",
                        UUID.randomUUID(), "RETRY_LATER")
                : new ApiError("REQUEST_REJECTED", "The request was rejected", UUID.randomUUID());
        json.writeValue(response.getOutputStream(), body);
    }
}
