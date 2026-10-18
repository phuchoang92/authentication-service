package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.LocalDateTime;

/**
 * Database-only projection of the locked Customer/device rows.
 *
 * <p>Component names match the query aliases so the row mapper binds by name, not by position.
 * {@code deviceExpiresAt} stays a {@link LocalDateTime}: the column is {@code datetime(6)} with
 * no zone, so interpreting it is a semantic decision owned by the adapter, not the row reader.
 */
public record LoginSessionSecurityView(String customerStatus,
                                       long customerSecurityVersion,
                                       long credentialSecurityVersion,
                                       long customerStatusVersion,
                                       String deviceStatus,
                                       boolean devicePrimary,
                                       LocalDateTime deviceExpiresAt,
                                       long deviceSecurityVersion,
                                       boolean biometricEnabled) { }
