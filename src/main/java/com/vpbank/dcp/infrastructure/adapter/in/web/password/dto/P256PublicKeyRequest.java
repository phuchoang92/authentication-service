package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Wire syntax only; the cryptographic adapter validates the actual curve point.
 */
public record P256PublicKeyRequest(@NotNull @Pattern(regexp = "EC") String kty,
                                   @NotNull @Pattern(regexp = "P-256") String crv,
                                   @NotNull @Pattern(regexp = "[A-Za-z0-9_-]{43}") String x,
                                   @NotNull @Pattern(regexp = "[A-Za-z0-9_-]{43}") String y) {
}
