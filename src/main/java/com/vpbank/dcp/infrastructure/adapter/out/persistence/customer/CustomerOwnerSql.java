package com.vpbank.dcp.infrastructure.adapter.out.persistence.customer;

final class CustomerOwnerSql {

    static final String FIND_JOURNEY = """
            SELECT BIN_TO_UUID(journey_id) FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN'
            """;

    static final String LOCK_SUBJECT = """
            SELECT BIN_TO_UUID(id), customer_status_version, customer_last_block_version,
                   customer_status_checked_at, status
              FROM auth_customer WHERE customer_id = :customerId FOR UPDATE
            """;

    static final String INSERT_SUBJECT = """
            INSERT INTO auth_customer
              (id, customer_id, customer_status_version, customer_last_block_version,
               customer_status_checked_at, status, policy_version, created_at, updated_at)
            VALUES (UUID_TO_BIN(:subjectId), :customerId, :statusVersion, :blockVersion,
                    :checkedAt, 'ELIGIBLE', :policyVersion, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
            """;

    static final String UPDATE_SNAPSHOT = """
            UPDATE auth_customer
               SET customer_status_version = :statusVersion,
                   customer_status_checked_at = GREATEST(customer_status_checked_at, :checkedAt),
                   version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:subjectId) AND status = 'ELIGIBLE'
               AND customer_last_block_version = :blockVersion
               AND customer_status_version <= :statusVersion
               AND version < 9007199254740991
            """;

    static final String LOCK_IDENTITY = """
            SELECT provider_subject, status FROM auth_identity_link
             WHERE subject_id = UUID_TO_BIN(:subjectId) AND issuer = :issuer FOR UPDATE
            """;

    static final String INSERT_IDENTITY = """
            INSERT INTO auth_identity_link
              (id, subject_id, issuer, provider_subject, status, created_at)
            VALUES (UUID_TO_BIN(:linkId), UUID_TO_BIN(:subjectId), :issuer,
                    :providerSubject, 'ACTIVE', UTC_TIMESTAMP(6))
            """;

    static final String LOCK_APP = """
            SELECT status FROM auth_subject_app
             WHERE subject_id = UUID_TO_BIN(:subjectId) AND app_id = :appId FOR UPDATE
            """;

    static final String INSERT_APP = """
            INSERT INTO auth_subject_app
              (subject_id, app_id, status, created_at, updated_at)
            VALUES (UUID_TO_BIN(:subjectId), :appId, 'ACTIVE',
                    UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
            """;

    static final String SUBJECT_GUARD_DENIES = """
            SELECT COUNT(*) FROM auth_security_guard g
              JOIN auth_customer s ON s.id = g.subject_id
             WHERE g.scope = 'SUBJECT' AND g.scope_id = UUID_TO_BIN(:subjectId)
               AND (g.deny = 1
                    OR g.min_customer_security_version > s.customer_security_version
                    OR g.min_credential_security_version > s.credential_security_version
                    OR g.min_device_security_version > 0)
            """;

    static final String ATTACH_JOURNEY = """
            UPDATE auth_login_journey
               SET subject_id = UUID_TO_BIN(:subjectId), version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId) AND app_id = :appId
               AND state = 'CREDENTIAL_PROCESSING' AND subject_id IS NULL
               AND journey_deadline > UTC_TIMESTAMP(6)
               AND version < 9007199254740991
            """;

    static final String CONFIRM_OPERATION = """
            UPDATE auth_operation
               SET subject_id = UUID_TO_BIN(:subjectId), state = 'CONFIRMED',
                   version = version + 1, updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId) AND journey_id = UUID_TO_BIN(:journeyId)
               AND app_id = :appId AND kind = 'PASSWORD_LOGIN'
               AND state = 'VERIFIED' AND subject_id IS NULL
               AND deadline > UTC_TIMESTAMP(6)
               AND version < 9007199254740991
            """;

    private CustomerOwnerSql() { }
}
