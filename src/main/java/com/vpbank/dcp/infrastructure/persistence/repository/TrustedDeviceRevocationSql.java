package com.vpbank.dcp.infrastructure.persistence.repository;

final class TrustedDeviceRevocationSql {
    static final String LOCK_CUSTOMER = """
            SELECT id FROM auth_customer
             WHERE id = UUID_TO_BIN(:customerId)
             FOR UPDATE
            """;

    static final String FIND_PRIMARY = """
            SELECT BIN_TO_UUID(id) FROM auth_trusted_device
             WHERE auth_customer_id = UUID_TO_BIN(:customerId)
               AND channel = :channel AND is_primary = 1
            """;

    static final String LOCK_DEVICE = """
            SELECT status, version, device_security_version
              FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
             FOR UPDATE
            """;

    static final String REVOKE_DEVICE = """
            UPDATE auth_trusted_device
               SET status = 'REVOKED', is_primary = 0, revoked_at = :occurredAt,
                   revoked_reason = :reasonCode, revoked_by_type = :actorType,
                   revoked_by_id = :actorId, device_security_version = device_security_version + 1,
                   version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
               AND status IN ('ACTIVE','PENDING_RESET') AND version = :expectedVersion
               AND device_security_version < 9007199254740991
            """;

    private TrustedDeviceRevocationSql() { }
}
