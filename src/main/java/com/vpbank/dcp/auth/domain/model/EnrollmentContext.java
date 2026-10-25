package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import java.util.Objects;
import lombok.Builder;

/**
 * What a restricted session remembers between init, verify and confirm: the enrollment, the device
 * key the app presented (or the stored one), the server key pair of this transaction (Ksrv; its
 * private part lives only here, DD 20 §4) and the digest of the challenge sent. Never persisted in SQL.
 */
@Builder(toBuilder = true)
public record EnrollmentContext(EnrollmentId enrollmentId, String devicePublicJwk, DevicePlatform platform,
                                String serverPublicJwk, String serverPrivateJwk, String challengeDigest,
                                boolean keyProven) {
    public EnrollmentContext {
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        Objects.requireNonNull(devicePublicJwk, "devicePublicJwk");
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(serverPublicJwk, "serverPublicJwk");
        Objects.requireNonNull(serverPrivateJwk, "serverPrivateJwk");
        Objects.requireNonNull(challengeDigest, "challengeDigest");
    }

    public EnrollmentContext proven() {
        return toBuilder().keyProven(true).build();
    }

    @Override
    public String toString() {
        return "EnrollmentContext[enrollmentId=" + enrollmentId + ", keyProven=" + keyProven + ", redacted]";
    }
}
