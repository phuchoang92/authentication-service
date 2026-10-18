package com.vpbank.dcp.infrastructure.adapter.in.web.session.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Flow 16 wire request. {@code admittedAt} stays a string so the exact ISO-8601 instant the
 * BFF fixed at admission is parsed in one place, the controller.
 */
public record SessionExtensionRequest(@NotNull @Valid SessionLookup sessionLookup,
                                      @NotNull @Pattern(regexp = UUID) String admissionId,
                                      @NotNull String admittedAt,
                                      @NotNull @Pattern(regexp = "[a-z0-9._-]{1,64}") String routeId,
                                      @NotNull @Pattern(regexp = B64_43) String requestKeyJkt) {

    static final String B64_43 = "[A-Za-z0-9_-]{43}";
    static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

    public record SessionLookup(@NotNull @Pattern(regexp = "[A-Za-z0-9_-]{1,16}") String lookupKeyVersion,
                                @NotNull @Pattern(regexp = B64_43) String lookupDigest) {
    }
}
