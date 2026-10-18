package com.vpbank.dcp.infrastructure.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Trusted-device continuation (draft doc 20). The restricted session has one TTL and no separate
 * absolute limit. {@code maximumActiveDevices} has no default: it is a bank policy value.
 */
@Validated
@ConfigurationProperties(prefix = "auth.trusted-device")
public record TrustedDeviceProperties(@Min(60) @Max(1800) long restrictedSessionTtlSeconds,
                                      @Min(1) @Max(10) int verifyMaxAttempts,
                                      @Min(1) @Max(90) int trustLifetimeDays,
                                      @Min(1) @Max(20) int maximumActiveDevices,
                                      @NotBlank @Size(max = 64) String trustPolicyVersion,
                                      @NotNull @Valid ServerKeyWrapping serverKeyWrapping,
                                      @NotNull @Valid PinnedSigner bffAssertion,
                                      @NotNull @Valid Mfa mfa) {

    /** AES-256 keys that wrap each device's Ksrv private key, by key ID. */
    public record ServerKeyWrapping(@NotBlank String activeKeyId,
                                    @NotEmpty Map<String, String> keysBase64) {
        @Override
        public String toString() {
            return "ServerKeyWrapping[redacted, activeKeyId=" + activeKeyId + "]";
        }
    }

    /** A pinned ES256 signer: no key is ever fetched from the token itself. */
    public record PinnedSigner(@NotBlank String issuer, @NotBlank String keyId,
                               @NotBlank String publicJwk) {
    }

    public record Mfa(@NotBlank String origin, @Min(1) @Max(8000) long requestTimeoutMs,
                      @NotNull @Valid PinnedSigner receipt) {
    }
}
