package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * {@code POST /internal/v1/service-tokens} (slice 12): the scope the caller wants and, when the scope binds the
 * token to a business journey, the journey's reference (the onboarding request ID). The caller itself comes
 * from the verified client assertion, never from the body.
 */
public record IssueServiceTokenRequest(

        @NotBlank(message = "{auth.required}")
        @Size(max = 32, message = "{auth.tooLong}")
        String scope,

        @Size(max = 128, message = "{auth.tooLong}")
        @Pattern(regexp = "[A-Za-z0-9._:-]*", message = "{auth.format}")
        String businessReference) { }
