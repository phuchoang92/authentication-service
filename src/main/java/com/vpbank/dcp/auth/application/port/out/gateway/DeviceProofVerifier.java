package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import java.time.Instant;
import lombok.NonNull;

/**
 * Checks the proof a trusted device signs at login (slice 13) under the public key its trusted row holds:
 * the signature over this login's bound fields, and the time window. Pure computation, no I/O; the
 * one-time use of the nonce is the {@code LoginProofReplayStore}'s job.
 */
public interface DeviceProofVerifier {

    sealed interface Outcome {
        /** A genuine, current proof, and how long its nonce must be remembered (until it could no longer pass the time check). */
        record Proven(@NonNull Instant rememberUntil) implements Outcome {
        }

        /** Anything else: another key, other bindings, out of time, unusable stored key. One answer, no detail. */
        record Rejected() implements Outcome {
        }
    }

    /** {@code devicePublicJwk} is the JWK text the trusted row stores for the device. */
    Outcome verify(String devicePublicJwk, DeviceProof proof, DeviceProofBindings bindings);
}
