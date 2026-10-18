package com.vpbank.dcp.core.port.out.pending;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Restricted login state. None of these values grants banking API access. */
public record PendingMfaLogin(Identity identity, Keys keys, Mfa mfa, Versions versions) {
    public PendingMfaLogin {
        Objects.requireNonNull(identity);
        Objects.requireNonNull(keys);
        Objects.requireNonNull(mfa);
        Objects.requireNonNull(versions);
    }

    public record Identity(UUID operationId, SubjectId owner, CustomerNumber customerNumber,
                           BindingId bindingId, String channel, String installationId) {
        public Identity {
            if (operationId == null || owner == null || bindingId == null
                    || customerNumber == null
                    || channel == null || channel.isBlank()
                    || installationId == null || installationId.isBlank()) {
                throw new InvalidPendingMfaLoginException();
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
                throw new InvalidPendingMfaLoginException();
            }
        }
    }

    /** The MFA transaction Auth started. Auth stores the identifier and nothing else. */
    public record Mfa(String authenticationId, String transactionId, Instant expiresAt) {
        public Mfa {
            if (authenticationId == null || !authenticationId.matches("[A-Za-z0-9_-]{22,64}")
                    || transactionId == null || !transactionId.matches("[A-Za-z0-9_-]{22,64}")
                    || expiresAt == null) {
                throw new InvalidPendingMfaLoginException();
            }
        }
    }

    public record Versions(long customerStatusVersion, long deviceSecurityVersion,
                           UUID generation) {
        public Versions {
            if (customerStatusVersion < 0 || deviceSecurityVersion < 0 || generation == null) {
                throw new InvalidPendingMfaLoginException();
            }
        }
    }

    @Override
    public String toString() {
        return "PendingMfaLogin[redacted]";
    }
}
