package com.vpbank.dcp.infrastructure.persistence.repository;

/**
 * Complete statements for the password-session capability; no query assembly in methods.
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

    static final String CURRENT_FACTS = """
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
                             AND cr.expires_at > UTC_TIMESTAMP(6))
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

    static final String EXISTING_INTENT = """
            SELECT BIN_TO_UUID(id) FROM auth_authority_intent
             WHERE operation_id = UUID_TO_BIN(:operationId)
            """;

    static final String INSERT_INTENT = """
            INSERT INTO auth_authority_intent
              (id, subject_id, app_id, journey_id, operation_id, binding_id, request_jkt,
               kind, state, generation, session_id, token_lookup_digest, lookup_key_version,
               expected_session_version, customer_security_version,
               credential_security_version, device_security_version, candidate_digest,
               deadline, idle_expires_at, absolute_expires_at, created_at, updated_at)
            VALUES (UUID_TO_BIN(:intentId), UUID_TO_BIN(:subjectId), :appId,
                    UUID_TO_BIN(:journeyId), UUID_TO_BIN(:operationId), UUID_TO_BIN(:bindingId),
                    :requestJkt, 'ACTIVATE', 'READY', UUID_TO_BIN(:generation),
                    UUID_TO_BIN(:sessionId), :lookupDigest, :lookupVersion, 0,
                    :customerVersion, :credentialVersion, :deviceVersion, :candidateDigest,
                    :absoluteExpiry, :idleExpiry, :absoluteExpiry, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
            """;

    static final String INSERT_ESCROW = """
            INSERT INTO auth_result_escrow
              (id, operation_id, request_jkt, command_digest, authority_intent_id,
               protected_result, encryption_key_id, result_digest, delivery_deadline,
               created_at, envelope_version, envelope_algorithm, recipient_key_thumbprint)
            SELECT UUID_TO_BIN(:escrowId), o.id, o.request_jkt, o.command_digest,
                   UUID_TO_BIN(:intentId), :protectedResult, 'APP_KENC_V1', :resultDigest,
                   :deliveryDeadline, UTC_TIMESTAMP(6), 1, 'ECDH-ES+A256GCM',
                   j.response_key_thumbprint
              FROM auth_operation o JOIN auth_login_journey j ON j.id = o.journey_id
             WHERE o.id = UUID_TO_BIN(:operationId) AND o.state = 'CONFIRMED'
            """;

    static final String FINALIZING_JOURNEY = """
            UPDATE auth_login_journey SET state = 'FINALIZING', route = 'LAST_TRUSTED',
                   resolved_binding_id = UUID_TO_BIN(:bindingId), version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId) AND state = 'CREDENTIAL_PROCESSING'
               AND journey_deadline > UTC_TIMESTAMP(6) AND version < 9007199254740991
            """;

    static final String PREPARED = """
            SELECT BIN_TO_UUID(i.id), BIN_TO_UUID(i.session_id), BIN_TO_UUID(i.generation),
                   i.lookup_key_version, i.token_lookup_digest, i.candidate_digest,
                   i.idle_expires_at, i.absolute_expires_at, e.delivery_deadline,
                   e.protected_result, e.result_digest,
                   i.customer_security_version, i.credential_security_version,
                   i.device_security_version, i.request_jkt, BIN_TO_UUID(i.binding_id),
                   BIN_TO_UUID(i.subject_id)
              FROM auth_authority_intent i
              JOIN auth_result_escrow e ON e.authority_intent_id = i.id
             WHERE i.operation_id = UUID_TO_BIN(:operationId)
               AND i.kind = 'ACTIVATE' AND i.state IN ('READY','APPLIED','COMPLETED')
               AND e.erased_at IS NULL AND e.delivery_deadline > UTC_TIMESTAMP(6)
            """;

    static final String MARK_INTENT_APPLIED = """
            UPDATE auth_authority_intent SET state = 'COMPLETED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:intentId) AND operation_id = UUID_TO_BIN(:operationId)
               AND kind = 'ACTIVATE' AND state = 'READY' AND deadline > UTC_TIMESTAMP(6)
               AND version < 9007199254740991
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

    static final String COMPLETED = """
            SELECT state FROM auth_authority_intent
             WHERE id = UUID_TO_BIN(:intentId) AND operation_id = UUID_TO_BIN(:operationId)
            """;

    private PasswordSessionSql() {
    }
}
