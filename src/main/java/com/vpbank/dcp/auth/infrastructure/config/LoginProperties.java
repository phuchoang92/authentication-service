package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Login settings; read only when {@code auth.login.enabled=true}. {@code deviceProofRequired} (slice 13) makes
 * every MOBILE login carry the device key and its signed proof; off until the apps sign one.
 */
@Validated
@ConfigurationProperties(prefix = "auth.login")
public record LoginProperties(boolean enabled, @Valid @NotNull Keycloak keycloak,
                              @Valid @NotNull @DefaultValue Lockout lockout,
                              @Min(1) @DefaultValue("3") int enrollmentMaxVerifyAttempts,
                              @Valid @NotNull @DefaultValue Approval approval,
                              @DefaultValue("false") boolean deviceProofRequired) {

    /**
     * Slice 6: approval of a new device by the current primary device (QR authorization token). A request belongs
     * to the device and waits a day (slice 11), so the new device may log in again to poll and claim it.
     */
    public record Approval(@NotNull @DefaultValue("PT24H") Duration pendingWindow,
                           @NotNull @DefaultValue("PT180S") Duration tokenLifetime,
                           @Min(1) @DefaultValue("5") int maxClaimAttempts,
                           @Min(1) @DefaultValue("3") int maxPendingDevices) {
    }

    /**
     * Escalating lockout (slice 3): CAPTCHA after N failures (default 1 since 2026-11-09), temporary locks at given failure
     * counts, permanent at the last. An absent {@code temporaryLocks} map means 3 → 15 min, 4 → 24 h
     * (Spring cannot default a map through {@code @DefaultValue}).
     */
    public record Lockout(@Min(1) @DefaultValue("1") int captchaAfter,
                          Map<Integer, Duration> temporaryLocks,
                          @Min(2) @DefaultValue("5") int permanentAt,
                          @NotNull @DefaultValue("PT5M") Duration captchaLifetime) {
        public Map<Integer, Duration> temporaryLocksOrDefault() {
            return temporaryLocks == null || temporaryLocks.isEmpty()
                    ? Map.of(3, Duration.ofMinutes(15), 4, Duration.ofHours(24)) : temporaryLocks;
        }
    }

    /** Direct Grant client. The issuer is {@code <baseUrl>/realms/<realm>} and must match the stored identity. */
    public record Keycloak(@NotBlank String baseUrl,
                           @NotBlank String realm,
                           @NotBlank String clientId,
                           @NotBlank String clientSecret,
                           @NotNull @DefaultValue("PT3S") Duration timeout) {
        public String issuer() {
            return baseUrl.replaceAll("/+$", "") + "/realms/" + realm;
        }

        @Override
        public String toString() {
            return "Keycloak[baseUrl=" + baseUrl + ", realm=" + realm + ", clientId=" + clientId + "]";
        }
    }

    @Override
    public String toString() {
        return "LoginProperties[enabled=" + enabled + ", " + keycloak + "]";
    }
}
