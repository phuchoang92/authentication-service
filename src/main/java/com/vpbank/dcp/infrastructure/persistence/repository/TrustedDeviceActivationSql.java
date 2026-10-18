package com.vpbank.dcp.infrastructure.persistence.repository;

/** One trust commit. Every statement runs inside the caller's single SQL transaction. */
final class TrustedDeviceActivationSql {
    static final String STORED_KEY = """
            SELECT device_public_key AS public_key_spki, device_public_key_hash AS public_key_hash
              FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
            """;

    static final String LOCK_CUSTOMER = """
            SELECT status, customer_status_version AS status_version FROM auth_customer
             WHERE id = UUID_TO_BIN(:customerId)
             FOR UPDATE
            """;

    static final String LOCK_PRIMARY = """
            SELECT BIN_TO_UUID(id) AS binding_id FROM auth_trusted_device
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
               AND is_primary = 1
             FOR UPDATE
            """;

    static final String LOCK_DEVICE = """
            SELECT status, expires_at > :now AS unexpired,
                   device_security_version AS security_version,
                   device_public_key_hash AS public_key_hash, device_public_key AS public_key
              FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
               AND auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
             FOR UPDATE
            """;

    static final String LOCK_LIVE_BY_DEVICE_ID = """
            SELECT BIN_TO_UUID(id) AS binding_id FROM auth_trusted_device
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
               AND device_id_lookup = :lookup AND device_id_lookup_key_id = :lookupKeyId
               AND live_slot = 1
             FOR UPDATE
            """;

    /** A kept, still valid binding: new Ksrv, authenticated now. */
    static final String KEEP_BINDING = """
            UPDATE auth_trusted_device
               SET server_key_id = :serverKeyId, server_key_ciphertext = :serverKeyCiphertext,
                   last_authenticated_at = :now, version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:bindingId) AND status = 'ACTIVE'
               AND expires_at > :now AND device_security_version = :expectedSecurityVersion
            """;

    /** An expired binding leaves the live set without a revocation event. */
    static final String MARK_EXPIRED = """
            UPDATE auth_trusted_device
               SET status = 'EXPIRED', is_primary = 0,
                   device_security_version = device_security_version + 1,
                   version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:bindingId) AND status IN ('ACTIVE','PENDING_RESET')
               AND device_security_version < 9007199254740991
            """;

    static final String REVOKE_BY_SYSTEM = """
            UPDATE auth_trusted_device
               SET status = 'REVOKED', is_primary = 0, revoked_at = :now,
                   revoked_reason = :reasonCode, revoked_by_type = 'SYSTEM',
                   revoked_by_id = 'authentication-service',
                   device_security_version = device_security_version + 1,
                   version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:bindingId) AND status IN ('ACTIVE','PENDING_RESET')
               AND device_security_version < 9007199254740991
            """;

    static final String SECURITY_VERSION = """
            SELECT device_security_version AS security_version FROM auth_trusted_device
             WHERE id = UUID_TO_BIN(:bindingId)
            """;

    static final String INSERT_DEVICE = """
            INSERT INTO auth_trusted_device
              (id, auth_customer_id, channel, device_id_lookup, device_id_lookup_key_id,
               device_id_ciphertext, device_id_key_id, platform, label, status,
               device_public_key, device_public_key_hash, device_key_algorithm,
               trust_method, trust_policy_version, possession_assurance,
               trusted_at, expires_at, last_authenticated_at,
               server_key_id, server_key_ciphertext, created_at, updated_at)
            VALUES (UUID_TO_BIN(:bindingId), UUID_TO_BIN(:customerId), :channel, :lookup,
                    :lookupKeyId, :deviceIdCiphertext, :deviceIdKeyId, :platform, :label,
                    'ACTIVE', :publicKey, :publicKeyHash, 'ES256', :trustMethod,
                    :trustPolicyVersion, 'MFA_KEY_POSSESSION', :now, :expiresAt, :now,
                    :serverKeyId, :serverKeyCiphertext, :now, :now)
            """;

    static final String CLEAR_PRIMARY = """
            UPDATE auth_trusted_device
               SET is_primary = 0, version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
               AND is_primary = 1
            """;

    static final String SET_PRIMARY = """
            UPDATE auth_trusted_device
               SET is_primary = 1, version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:bindingId) AND status = 'ACTIVE' AND trusted_at IS NOT NULL
            """;

    static final String REVOKE_BIOMETRICS = """
            UPDATE auth_biometric_login
               SET status = 'REVOKED', revoked_at = :now, version = version + 1
             WHERE trusted_device_id = UUID_TO_BIN(:bindingId)
               AND status IN ('ACTIVE','SUSPENDED')
            """;

    static final String COUNT_LIVE = """
            SELECT COUNT(*) FROM auth_trusted_device
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
               AND live_slot = 1
            """;

    /** Never authenticated counts as oldest; ties fall back to creation time. */
    static final String LOCK_OLDEST_LIVE_EXCEPT = """
            SELECT BIN_TO_UUID(id) AS binding_id FROM auth_trusted_device
             WHERE auth_customer_id = UUID_TO_BIN(:customerId) AND channel = :channel
               AND live_slot = 1 AND id <> UUID_TO_BIN(:keepBindingId)
             ORDER BY last_authenticated_at IS NOT NULL, last_authenticated_at, created_at, id
             LIMIT 1
             FOR UPDATE
            """;

    private TrustedDeviceActivationSql() {
    }
}
