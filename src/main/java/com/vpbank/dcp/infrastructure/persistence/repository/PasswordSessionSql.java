package com.vpbank.dcp.infrastructure.persistence.repository;

/**
 * Password-source eligibility, locks and journey transitions; complete statements only.
 */
final class PasswordSessionSql {
    static final String OPERATION_SUBJECT = """
            SELECT BIN_TO_UUID(subject_id) FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN'
            """;

    static final String LOCK_SUBJECT = """
            SELECT id FROM auth_customer WHERE id = UUID_TO_BIN(:subjectId) FOR UPDATE
            """;

    static final String LOCK_SUBJECT_APP = """
            SELECT subject_id FROM auth_subject_app
             WHERE subject_id = UUID_TO_BIN(:subjectId) AND app_id = :appId FOR UPDATE
            """;

    static final String LOCK_BINDING = """
            SELECT id FROM auth_device_binding
             WHERE id = UUID_TO_BIN(:bindingId) AND subject_id = UUID_TO_BIN(:subjectId)
               AND app_id = :appId FOR UPDATE
            """;

    static final String LOCK_JOURNEY = """
            SELECT id FROM auth_login_journey WHERE id = UUID_TO_BIN(:journeyId) FOR UPDATE
            """;

    static final String LOCK_OPERATION = """
            SELECT id FROM auth_operation WHERE id = UUID_TO_BIN(:operationId) FOR UPDATE
            """;

    static final String CURRENT_SNAPSHOT = """
            SELECT BIN_TO_UUID(o.id), BIN_TO_UUID(j.id), BIN_TO_UUID(s.id), o.app_id,
                   BIN_TO_UUID(b.id), j.request_jkt,
                   CAST(j.request_public_jwk AS CHAR), CAST(j.response_public_jwk AS CHAR),
                   j.device_proof_jkt, s.customer_security_version,
                   s.credential_security_version, b.device_security_version,
                   s.customer_status_version, s.customer_status_checked_at,
                   b.platform_assurance,
                   EXISTS(SELECT 1 FROM auth_credential_reference cr
                           WHERE cr.binding_id = b.id AND cr.subject_id = s.id
                             AND cr.app_id = o.app_id AND cr.type = 'BIOMETRIC'
                             AND cr.observed_status = 'ACTIVE'
                             AND cr.expires_at > UTC_TIMESTAMP(6)) AS biometric_capable
              FROM auth_operation o
              JOIN auth_login_journey j ON j.id = o.journey_id
              JOIN auth_customer s ON s.id = o.subject_id
              JOIN auth_subject_app a ON a.subject_id = s.id AND a.app_id = o.app_id
              JOIN auth_device_binding b ON b.id = j.candidate_binding_id
                   AND b.subject_id = s.id AND b.app_id = o.app_id
              JOIN auth_device_key k ON k.binding_id = b.id
                   AND k.subject_id = s.id AND k.app_id = o.app_id
                   AND k.purpose = 'DEVICE_POSSESSION'
             WHERE o.id = UUID_TO_BIN(:operationId)
               AND o.subject_id = UUID_TO_BIN(:subjectId)
               AND o.kind = 'PASSWORD_LOGIN' AND o.state IN ('CONFIRMED','COMPLETED')
               AND j.subject_id = s.id AND j.app_id = o.app_id
               AND j.state IN ('CREDENTIAL_PROCESSING','FINALIZING','COMPLETED')
               AND j.installation_hash = b.installation_hash
               AND j.device_proof_jkt = k.jkt
               AND a.last_successful_binding_id = b.id AND a.status = 'ACTIVE'
               AND s.status = 'ELIGIBLE' AND b.status = 'ACTIVE'
               AND b.expires_at > UTC_TIMESTAMP(6)
               AND k.status = 'ACTIVE' AND k.expires_at > UTC_TIMESTAMP(6)
            """;

    static final String FINALIZING_JOURNEY = """
            UPDATE auth_login_journey SET state = 'FINALIZING', route = 'LAST_TRUSTED',
                   resolved_binding_id = UUID_TO_BIN(:bindingId), version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId) AND state = 'CREDENTIAL_PROCESSING'
               AND journey_deadline > UTC_TIMESTAMP(6) AND version < 9007199254740991
            """;

    static final String COMPLETE_JOURNEY = """
            UPDATE auth_login_journey SET state = 'COMPLETED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId) AND state = 'FINALIZING'
               AND version < 9007199254740991
            """;

    static final String COMPLETE_OPERATION = """
            UPDATE auth_operation SET state = 'COMPLETED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId) AND state = 'CONFIRMED'
               AND kind = 'PASSWORD_LOGIN' AND version < 9007199254740991
            """;

    private PasswordSessionSql() {
    }
}
