package com.vpbank.dcp.infrastructure.persistence.repository;

final class TrustedDeviceRevocationSql {
    static final String LOCK_CUSTOMER_APP = """
            SELECT BIN_TO_UUID(primary_trusted_device_id), version
              FROM auth_customer_app
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND app_id = :appId
             FOR UPDATE
            """;

    static final String LOCK_DEVICE = """
            SELECT status, version, device_security_version
              FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId) AND app_id = :appId
             FOR UPDATE
            """;

    static final String REVOKE_DEVICE = """
            UPDATE auth_trusted_device
               SET status = 'REVOKED', revoked_at = :occurredAt,
                   revoked_reason = :reasonCode, revoked_by_type = :actorType,
                   revoked_by_id = :actorId, device_security_version = device_security_version + 1,
                   version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId) AND app_id = :appId
               AND status IN ('ACTIVE','PENDING_RESET') AND version = :expectedVersion
               AND device_security_version < 9007199254740991
            """;

    static final String CLEAR_PRIMARY = """
            UPDATE auth_customer_app
               SET primary_trusted_device_id = NULL, version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND app_id = :appId
               AND primary_trusted_device_id = UUID_TO_BIN(:bindingId)
               AND version = :expectedVersion AND version < 9007199254740991
            """;

    private TrustedDeviceRevocationSql() { }
}
