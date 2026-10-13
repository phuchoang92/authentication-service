package com.vpbank.dcp.infrastructure.persistence.repository;

final class SecurityAuditSql {
    static final String FIND_DEVICE_REVOKE = """
            SELECT BIN_TO_UUID(r.operation_id), r.device_security_version,
                   EXISTS(SELECT 1 FROM auth_security_audit_event p
                           WHERE p.operation_id = r.operation_id
                             AND p.event_type = 'PRIMARY_DEVICE_CHANGED'
                             AND p.previous_primary_device_id = r.trusted_device_id
                             AND p.new_primary_device_id IS NULL)
              FROM auth_security_audit_event r
             WHERE r.event_type = 'DEVICE_REVOKED'
               AND r.trusted_device_id = UUID_TO_BIN(:bindingId)
               AND r.auth_customer_id = UUID_TO_BIN(:customerId) AND r.app_id = :appId
            """;

    static final String INSERT_DEVICE_REVOKE = """
            INSERT INTO auth_security_audit_event
              (id, auth_customer_id, app_id, operation_id, event_sequence, event_type,
               trusted_device_id, device_security_version, reason_code,
               actor_type, actor_id, occurred_at, recorded_at)
            VALUES (UUID_TO_BIN(:eventId), UUID_TO_BIN(:customerId), :appId,
                    UUID_TO_BIN(:operationId), 1, 'DEVICE_REVOKED',
                    UUID_TO_BIN(:bindingId), :deviceSecurityVersion, :reasonCode,
                    :actorType, :actorId, :occurredAt, UTC_TIMESTAMP(6))
            """;

    static final String INSERT_PRIMARY_CLEARED = """
            INSERT INTO auth_security_audit_event
              (id, auth_customer_id, app_id, operation_id, event_sequence, event_type,
               previous_primary_device_id, new_primary_device_id,
               actor_type, actor_id, occurred_at, recorded_at)
            VALUES (UUID_TO_BIN(:eventId), UUID_TO_BIN(:customerId), :appId,
                    UUID_TO_BIN(:operationId), 2, 'PRIMARY_DEVICE_CHANGED',
                    UUID_TO_BIN(:bindingId), NULL,
                    :actorType, :actorId, :occurredAt, UTC_TIMESTAMP(6))
            """;

    private SecurityAuditSql() { }
}
