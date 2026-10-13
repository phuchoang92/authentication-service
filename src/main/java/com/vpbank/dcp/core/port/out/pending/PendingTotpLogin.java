package com.vpbank.dcp.core.port.out.pending;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Restricted login state. None of these values grants banking API access. */
public record PendingTotpLogin(Identity identity, Keys keys, Challenge challenge, Versions versions) {
    public PendingTotpLogin {
        Objects.requireNonNull(identity);
        Objects.requireNonNull(keys);
        Objects.requireNonNull(challenge);
        Objects.requireNonNull(versions);
    }

    public record Identity(UUID operationId, UUID customerId, String customerExternalId,
                           UUID bindingId, String channel, String installationId) {
        public Identity {
            if (operationId == null || customerId == null || bindingId == null
                    || customerExternalId == null || customerExternalId.isBlank()
                    || channel == null || channel.isBlank()
                    || installationId == null || installationId.isBlank()) {
                throw new InvalidPendingTotpLoginException();
            }
        }
    }

    public record Keys(String requestKeyJkt, String requestPublicJwk,
                       String responsePublicJwk, String deviceKeyJkt) {
        public Keys {
            if (requestKeyJkt == null || requestKeyJkt.isBlank()
                    || requestPublicJwk == null || requestPublicJwk.isBlank()
                    || responsePublicJwk == null || responsePublicJwk.isBlank()
                    || deviceKeyJkt == null || deviceKeyJkt.isBlank()) {
                throw new InvalidPendingTotpLoginException();
            }
        }
    }

    public record Challenge(String authenticationId, String challengeId, Instant expiresAt) {
        public Challenge {
            if (authenticationId == null || !authenticationId.matches("[A-Za-z0-9_-]{22,64}")
                    || challengeId == null || !challengeId.matches("[A-Za-z0-9_-]{22,64}")
                    || expiresAt == null) {
                throw new InvalidPendingTotpLoginException();
            }
        }
    }

    public record Versions(long customerStatusVersion, long deviceSecurityVersion,
                           UUID generation) {
        public Versions {
            if (customerStatusVersion < 0 || deviceSecurityVersion < 0 || generation == null) {
                throw new InvalidPendingTotpLoginException();
            }
        }
    }

    @Override
    public String toString() {
        return "PendingTotpLogin[redacted]";
    }
}
