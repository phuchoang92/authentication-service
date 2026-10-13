package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** App public Kenc used to encrypt the session token delivered after authentication. */
public record TokenEncryptionKeyRequest(@NotNull @Min(1) @Max(1) Integer version,
                                           @NotNull @Pattern(regexp = "ECDH-ES\\+A256GCM") String algorithm,
                                           @NotNull @Pattern(regexp = "JWK") String format,
                                           @NotNull @Valid P256PublicKeyRequest publicJwk) {
}
