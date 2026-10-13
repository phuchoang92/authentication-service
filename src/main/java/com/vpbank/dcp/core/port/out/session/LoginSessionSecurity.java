package com.vpbank.dcp.core.port.out.session;

import java.time.Instant;
import java.util.UUID;

/** Current SQL security state needed before attempting to publish an ACTIVE session. */
public record LoginSessionSecurity(UUID customerId, UUID bindingId, String channel,
                                   boolean customerEligible, boolean deviceActive,
                                   boolean primary, Instant deviceExpiresAt,
                                   long customerSecurityVersion, long credentialSecurityVersion,
                                   long deviceSecurityVersion, long customerStatusVersion,
                                   boolean biometricEnabled) { }
