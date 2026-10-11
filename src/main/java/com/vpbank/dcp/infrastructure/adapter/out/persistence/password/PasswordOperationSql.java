package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

final class PasswordOperationSql {

    static final String INSERT_JOURNEY = """
            INSERT INTO auth_login_journey
              (id, app_id, method, purpose, installation_hash, request_jkt,
               request_public_jwk, candidate_binding_id, state,
               response_key_version, response_key_algorithm, response_key_format,
               response_key_thumbprint, response_public_jwk, credential_deadline,
               journey_deadline, created_at, updated_at)
            VALUES (UUID_TO_BIN(:journeyId), :appId, 'PASSWORD', 'LOGIN', :installationHash,
                    :requestJkt, :requestPublicJwk,
                    CASE WHEN :bindingId IS NULL THEN NULL ELSE UUID_TO_BIN(:bindingId) END,
                    'INITIALIZED', 1, 'ECDH-ES+A256GCM', 'JWK', :responseJkt,
                    :responsePublicJwk, :credentialDeadline, :journeyDeadline, :now, :now)
            """;

    static final String INSERT_OPERATION = """
            INSERT INTO auth_operation
              (id, journey_id, app_id, source, owner_scope, kind, idempotency_digest,
               command_digest, command_digest_key_id, request_jkt, state, deadline,
               created_at, updated_at)
            VALUES (UUID_TO_BIN(:operationId), UUID_TO_BIN(:journeyId), :appId,
                    'NATIVE', :ownerScope, 'PASSWORD_LOGIN', :idempotency,
                    :commandDigest, :commandKeyId, :requestJkt, 'RESERVED',
                    :deadline, :now, :now)
            """;

    static final String FIND_BY_IDEMPOTENCY = """
            SELECT BIN_TO_UUID(id), BIN_TO_UUID(journey_id), command_digest,
                   command_digest_key_id
              FROM auth_operation
             WHERE owner_scope = :ownerScope AND kind = 'PASSWORD_LOGIN'
               AND idempotency_digest = :idempotency
            """;

    static final String CLAIM_JOURNEY_FOR_DISPATCH = """
            UPDATE auth_login_journey journey
              JOIN auth_operation operation ON operation.journey_id = journey.id
               SET journey.state = 'CREDENTIAL_PROCESSING',
                   journey.version = journey.version + 1,
                   journey.updated_at = UTC_TIMESTAMP(6)
             WHERE operation.id = UUID_TO_BIN(:operationId)
               AND operation.kind = 'PASSWORD_LOGIN'
               AND operation.state = 'RESERVED'
               AND operation.deadline > UTC_TIMESTAMP(6)
               AND journey.state = 'INITIALIZED'
               AND journey.credential_deadline > UTC_TIMESTAMP(6)
               AND journey.version < 9007199254740991
            """;

    static final String CLAIM_DISPATCH = """
            UPDATE auth_operation
               SET state = 'DISPATCHED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId)
               AND kind = 'PASSWORD_LOGIN' AND state = 'RESERVED'
               AND deadline > UTC_TIMESTAMP(6)
               AND version < 9007199254740991
            """;

    static final String FIND_DISPATCH_STATE = """
            SELECT state FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN'
            """;

    static final String REJECT_JOURNEY = """
            UPDATE auth_login_journey journey
              JOIN auth_operation operation ON operation.journey_id = journey.id
               SET journey.state = 'FAILED', journey.version = journey.version + 1,
                   journey.updated_at = UTC_TIMESTAMP(6)
             WHERE operation.id = UUID_TO_BIN(:operationId)
               AND operation.kind = 'PASSWORD_LOGIN' AND operation.state = 'DISPATCHED'
               AND journey.state = 'CREDENTIAL_PROCESSING'
               AND journey.version < 9007199254740991
            """;

    static final String REJECT_OPERATION = """
            UPDATE auth_operation
               SET state = 'REJECTED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId)
               AND kind = 'PASSWORD_LOGIN' AND state = 'DISPATCHED'
               AND version < 9007199254740991
            """;

    static final String RECORD_UNCERTAIN = """
            UPDATE auth_operation
               SET state = 'UNCERTAIN', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId)
               AND kind = 'PASSWORD_LOGIN' AND state = 'DISPATCHED'
               AND version < 9007199254740991
            """;

    private PasswordOperationSql() { }
}
