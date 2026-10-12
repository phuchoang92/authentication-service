package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record ResponseEncryptionKeyRequest(@NotNull @Min(1) @Max(1) Integer version,
                                           @NotNull @Pattern(regexp = "ECDH-ES\\+A256GCM") String algorithm,
                                           @NotNull @Pattern(regexp = "JWK") String format,
                                           @NotNull @Valid P256PublicKeyRequest publicJwk) {
}
