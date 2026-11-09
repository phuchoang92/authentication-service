package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.time.Instant;

public sealed interface InitEnrollmentResult {
    /** Ksrv public key and the challenge sealed to the device key (compact JWE). */
    record KeyExchange(EnrollmentId enrollmentId, String serverPublicJwk, String challenge, Instant expiresAt)
            implements InitEnrollmentResult {
        @Override
        public String toString() {
            return "KeyExchange[enrollmentId=" + enrollmentId + ", redacted]";
        }
    }

    /** An unknown device sent no (usable) public key or no platform. */
    record DeviceKeyRequired() implements InitEnrollmentResult { }

    /** Not a restricted session, a repeated init naming another key, or a racing init of the same device. */
    record Conflict() implements InitEnrollmentResult { }

    record Unavailable() implements InitEnrollmentResult { }
}
