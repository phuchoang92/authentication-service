package com.vpbank.dcp.core.domain.session;

import java.util.Objects;

/** Independent assurance axes supplied by the confirmed authentication source. */
public record SessionAssurance(DevicePossession devicePossession, PlatformEvidence platformEvidence,
                               BiometricEnforcement biometricEnforcement) {
    public SessionAssurance {
        Objects.requireNonNull(devicePossession, "devicePossession");
        Objects.requireNonNull(platformEvidence, "platformEvidence");
        Objects.requireNonNull(biometricEnforcement, "biometricEnforcement");
    }

    public enum DevicePossession {
        MFA_KEY_POSSESSION("MFA_KEY_POSSESSION");

        private final String code;

        DevicePossession(String code) { this.code = code; }

        public String code() { return code; }
    }

    public enum PlatformEvidence {
        NONE("NONE");

        private final String code;

        PlatformEvidence(String code) { this.code = code; }

        public String code() { return code; }
    }

    public enum BiometricEnforcement {
        NOT_APPLICABLE("NOT_APPLICABLE"), CLIENT_ENFORCED("CLIENT_ENFORCED");

        private final String code;

        BiometricEnforcement(String code) { this.code = code; }

        public String code() { return code; }
    }
}
