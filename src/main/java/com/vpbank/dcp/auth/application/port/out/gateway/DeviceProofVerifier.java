package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.model.DeviceSigningKey;
import java.time.Instant;
import java.util.Objects;

/**
 * Checks the proof an app signs with its device key at login (slice 13): the signature under the key the
 * app sent, the exact claim set bound to this login, and the time window. Pure computation, no I/O; the
 * one-time use of the proof ID is the {@code LoginProofReplayStore}'s job.
 */
public interface DeviceProofVerifier {

    sealed interface Outcome {
        /**
         * A genuine, current proof: the key in its canonical form, the proof ID to remember and how long
         * to remember it (until the proof could no longer pass the time check).
         */
        record Proven(DeviceSigningKey key, String proofId, Instant rememberUntil) implements Outcome {
            public Proven {
                Objects.requireNonNull(key, "key");
                Objects.requireNonNull(proofId, "proofId");
                Objects.requireNonNull(rememberUntil, "rememberUntil");
            }
        }

        /** Anything else: wrong key, wrong shape, wrong bindings, expired. One answer, no detail. */
        record Rejected() implements Outcome {
        }
    }

    /** {@code devicePublicJwk} is the JWK text the app sent; {@code compactProof} is the compact JWS. */
    Outcome verify(String devicePublicJwk, String compactProof, DeviceProofBindings bindings);
}
