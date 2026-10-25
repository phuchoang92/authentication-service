package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

/** {@code POST /internal/v1/sessions/extend} (flow 16): the BFF names the session by its lookup, never by token. */
public record ExtendSessionRequest(
        @NotNull(message = "{auth.required}") @Valid SessionLookupDto sessionLookup,
        @Size(max = 64, message = "{auth.tooLong}") String admissionId,
        @NotNull(message = "{auth.required}") Instant admittedAt,
        @NotBlank(message = "{auth.required}") @Size(max = 64, message = "{auth.tooLong}") String routeId) {

    public record SessionLookupDto(
            @NotBlank(message = "{auth.required}") @Pattern(regexp = "k[1-9][0-9]{0,2}", message = "{auth.format}")
            String lookupKeyVersion,
            @NotBlank(message = "{auth.required}") @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "{auth.format}")
            String lookupDigest) { }
}
