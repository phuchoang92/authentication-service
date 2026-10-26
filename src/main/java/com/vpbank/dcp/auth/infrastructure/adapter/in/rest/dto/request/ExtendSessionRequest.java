package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;

/**
 * {@code POST /internal/v1/sessions/extend} (flow 16): the BFF names the session by channel and session ID
 * as carried in the token, never by the token's secret.
 */
public record ExtendSessionRequest(

        @NotNull(message = "{auth.required}")
        @Valid
        SessionLookupDto sessionLookup,

        @Size(max = 64, message = "{auth.tooLong}")
        String admissionId,

        @NotNull(message = "{auth.required}")
        Instant admittedAt,

        @NotBlank(message = "{auth.required}")
        @Size(max = 64, message = "{auth.tooLong}")
        String routeId) {

    public record SessionLookupDto(

            @NotBlank(message = "{auth.required}")
            @Pattern(regexp = "MOBILE|WEB", message = "{auth.format}")
            String channel,

            @NotBlank(message = "{auth.required}")
            @Pattern(regexp = "[0-9a-fA-F-]{36}", message = "{auth.format}")
            String sessionId) { }
}
