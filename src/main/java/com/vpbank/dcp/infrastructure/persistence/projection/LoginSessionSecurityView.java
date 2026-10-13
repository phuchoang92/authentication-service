package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;

/** Database-only projection of the locked Customer/device rows. */
public record LoginSessionSecurityView(String customerStatus,
                                       long customerSecurityVersion,
                                       long credentialSecurityVersion,
                                       long customerStatusVersion,
                                       String deviceStatus,
                                       boolean primary,
                                       Instant deviceExpiresAt,
                                       long deviceSecurityVersion,
                                       boolean biometricEnabled) { }
