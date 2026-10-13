package com.vpbank.dcp.infrastructure.persistence.repository;

final class LoginDeviceSql {
    static final String KEY_FOR_PROOF = """
            SELECT device_public_key, device_public_key_hash
              FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND status = 'ACTIVE'
               AND expires_at > UTC_TIMESTAMP(6)
            """;

    static final String CURRENT = """
            SELECT BIN_TO_UUID(id), BIN_TO_UUID(auth_customer_id), channel, platform,
                   device_id_lookup, device_id_lookup_key_id, status, is_primary,
                   expires_at, device_security_version, device_public_key,
                   device_public_key_hash
              FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId)
               AND channel = :channel
             FOR UPDATE
            """;

    private LoginDeviceSql() {
    }
}
