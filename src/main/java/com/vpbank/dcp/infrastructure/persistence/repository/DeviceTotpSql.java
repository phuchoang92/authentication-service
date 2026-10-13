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

    static final String LOCK_ACTIVE_CREDENTIAL = """
            SELECT BIN_TO_UUID(id), secret_ciphertext, secret_key_id, last_accepted_step,
                   failed_attempts, blocked_until, version
              FROM auth_device_totp_credential
             WHERE trusted_device_id = UUID_TO_BIN(:bindingId)
               AND status = 'ACTIVE'
             FOR UPDATE
            """;

    static final String CONSUME_STEP = """
            UPDATE auth_device_totp_credential
               SET last_accepted_step = :matchedStep, failed_attempts = 0,
                   blocked_until = NULL, version = version + 1
             WHERE id = UUID_TO_BIN(:credentialId)
               AND trusted_device_id = UUID_TO_BIN(:bindingId)
               AND status = 'ACTIVE'
               AND last_accepted_step < :matchedStep
               AND version = :expectedVersion
               AND version < 9007199254740991
            """;

    static final String RECORD_FAILURE = """
            UPDATE auth_device_totp_credential
               SET failed_attempts = :failedAttempts,
                   blocked_until = :blockedUntil,
                   version = version + 1
             WHERE id = UUID_TO_BIN(:credentialId)
               AND trusted_device_id = UUID_TO_BIN(:bindingId)
               AND status = 'ACTIVE'
               AND version = :expectedVersion
               AND version < 9007199254740991
            """;

    private DeviceTotpSql() { }
}
