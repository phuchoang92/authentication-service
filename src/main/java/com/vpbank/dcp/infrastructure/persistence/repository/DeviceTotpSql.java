package com.vpbank.dcp.infrastructure.persistence.repository;

final class DeviceTotpSql {
    static final String LOCK_ACTIVE_DEVICE = """
            SELECT id FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId)
               AND channel = :channel
               AND status = 'ACTIVE'
               AND expires_at > UTC_TIMESTAMP(6)
             FOR UPDATE
            """;

    private DeviceTotpSql() {
    }
}
