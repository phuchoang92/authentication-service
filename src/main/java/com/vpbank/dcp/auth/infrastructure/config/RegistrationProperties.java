package com.vpbank.dcp.auth.infrastructure.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/** Settings of registration; read only when {@code auth.registration.enabled=true}. */
@Validated
@ConfigurationProperties(prefix = "auth.registration")
public record RegistrationProperties(
        boolean enabled,
        /* Base64, at least 32 bytes: HMAC key of the stored request digest. */
        @NotBlank String requestDigestKeyBase64,
        /* Positive: a request may not expire before it is written. */
        @NotNull @DurationMin(seconds = 1) @DefaultValue("PT24H") Duration requestLifetime,
        @Min(8) @Max(64) @DefaultValue("12") int initialPasswordLength,
        @Valid @NotNull Customer customer,
        @Valid @NotNull Keycloak keycloak,
        @Valid @NotNull Notification notification) {

    public record Customer(@NotBlank String origin,
                           @NotBlank @DefaultValue("/internal/v1/customers/{customerId}/profile")
                           String profilePath,
                           String serviceToken,
                           @NotNull @DefaultValue("PT3S") Duration timeout) {
        @Override
        public String toString() {
            return "Customer[origin=" + origin + ", profilePath=" + profilePath + "]";
        }
    }

    public record Keycloak(@NotBlank String baseUrl,
                           @NotBlank String realm,
                           @NotBlank String adminClientId,
                           @NotBlank String adminClientSecret,
                           @NotNull @DefaultValue("PT3S") Duration timeout) {
        @Override
        public String toString() {
            return "Keycloak[baseUrl=" + baseUrl + ", realm=" + realm + "]";
        }
    }

    public record Notification(@NotBlank String origin,
                               @NotBlank @DefaultValue("/internal/v1/notifications/sms") String smsPath,
                               @NotBlank String serviceToken,
                               @NotNull @DefaultValue("PT3S") Duration timeout) {
        @Override
        public String toString() {
            return "Notification[origin=" + origin + ", smsPath=" + smsPath + "]";
        }
    }

    @Override
    public String toString() {
        return "RegistrationProperties[enabled=" + enabled + ", " + customer + ", " + keycloak
                + ", " + notification + "]";
    }
}
