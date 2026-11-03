package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;

/**
 * What a login says about the device's key, as the device routing needs it (slice 13).
 *
 * <ul>
 *   <li>{@link Proven}: the app signed a proof with the key; the routing compares it with the key the
 *       trusted row holds, and a first device is trusted with it.</li>
 *   <li>{@link Unproven}: the app sent a key without a proof, allowed only while the login proof is not
 *       required on the environment (the behaviour before slice 13: stored for a first device, never
 *       compared).</li>
 *   <li>{@link None}: no key at all (WEB, or a mobile login without a key while the proof is optional).</li>
 * </ul>
 */
public sealed interface DeviceKeyClaim {

    record Proven(DeviceSigningKey key) implements DeviceKeyClaim {
        public Proven {
            Objects.requireNonNull(key, "key");
        }
    }

    record Unproven(String publicJwk) implements DeviceKeyClaim {
        public Unproven {
            Objects.requireNonNull(publicJwk, "publicJwk");
        }
    }

    record None() implements DeviceKeyClaim {
    }

    /** The public key text to store when this login trusts the customer's first device; null for {@link None}. */
    default String publicJwkToStore() {
        return switch (this) {
            case Proven(DeviceSigningKey key) -> key.publicJwk();
            case Unproven(String publicJwk) -> publicJwk;
            case None() -> null;
        };
    }
}
