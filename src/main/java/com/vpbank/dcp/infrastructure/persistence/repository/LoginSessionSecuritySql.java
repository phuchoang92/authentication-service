package com.vpbank.dcp.infrastructure.persistence.repository;

final class LoginSessionSecuritySql {
    static final String CURRENT = """
            SELECT c.status, c.customer_security_version,
                   c.credential_security_version, c.customer_status_version,
                   d.status, d.is_primary, d.expires_at,
                   d.device_security_version,
                   EXISTS (SELECT 1 FROM auth_biometric_login b
                            WHERE b.trusted_device_id = d.id
                              AND b.auth_customer_id = c.id
                              AND b.channel = d.channel
                              AND b.status = 'ACTIVE')
              FROM auth_customer c
              JOIN auth_trusted_device d ON d.auth_customer_id = c.id
             WHERE c.id = UUID_TO_BIN(:customerId)
               AND d.id = UUID_TO_BIN(:bindingId)
               AND d.channel = :channel
             FOR UPDATE
            """;

    private LoginSessionSecuritySql() { }
}
