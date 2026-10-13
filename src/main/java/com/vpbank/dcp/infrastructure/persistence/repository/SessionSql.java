package com.vpbank.dcp.infrastructure.persistence.repository;

/** Complete session activation intent and escrow statements. */
final class SessionSql {
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

    static final String COMPLETED = """
            SELECT state FROM auth_authority_intent
             WHERE id = UUID_TO_BIN(:intentId) AND operation_id = UUID_TO_BIN(:operationId)
            """;

    private SessionSql() {
    }
}
