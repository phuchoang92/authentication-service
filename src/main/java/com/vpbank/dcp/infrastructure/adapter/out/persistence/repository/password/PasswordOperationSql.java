package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

final class PasswordOperationSql {

    static final String INSERT_JOURNEY = """
            INSERT INTO auth_login_journey
              (id, app_id, method, purpose, installation_hash, request_jkt,
               request_public_jwk, candidate_binding_id, device_proof_jkt, state,
               response_key_version, response_key_algorithm, response_key_format,
               response_key_thumbprint, response_public_jwk, credential_deadline,
               journey_deadline, created_at, updated_at)
            VALUES (UUID_TO_BIN(:journeyId), :appId, 'PASSWORD', 'LOGIN', :installationHash,
                    :requestJkt, :requestPublicJwk,
                    CASE WHEN :bindingId IS NULL THEN NULL ELSE UUID_TO_BIN(:bindingId) END,
                    :deviceProofJkt,
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

    static final String FIND_JOURNEY_ID = """
            SELECT BIN_TO_UUID(journey_id) FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN'
            """;

    static final String LOCK_JOURNEY = """
            SELECT state FROM auth_login_journey
             WHERE id = UUID_TO_BIN(:journeyId) FOR UPDATE
            """;

    static final String CLAIM_JOURNEY_FOR_DISPATCH = """
            UPDATE auth_login_journey
               SET state = 'CREDENTIAL_PROCESSING', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId)
               AND state = 'INITIALIZED'
               AND credential_deadline > UTC_TIMESTAMP(6)
               AND version < 9007199254740991
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

    static final String LOCK_DISPATCH_STATE = """
            SELECT state FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN' FOR UPDATE
            """;

    static final String READ_PROGRESS = """
            SELECT state FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN'
            """;

    static final String RECORD_VERIFIED_IDENTITY = """
            UPDATE auth_operation o
              JOIN auth_login_journey j ON j.id = o.journey_id
               SET o.state = 'VERIFIED', o.verified_issuer = :issuer,
                   o.verified_subject = :subject, o.verified_at = UTC_TIMESTAMP(6),
                   o.version = o.version + 1, o.updated_at = UTC_TIMESTAMP(6)
             WHERE o.id = UUID_TO_BIN(:operationId)
               AND o.kind = 'PASSWORD_LOGIN' AND o.state = 'DISPATCHED'
               AND j.state = 'CREDENTIAL_PROCESSING'
               AND o.deadline > UTC_TIMESTAMP(6)
               AND o.version < 9007199254740991
            """;

    static final String READ_VERIFIED_IDENTITY = """
            SELECT verified_issuer, verified_subject FROM auth_operation
             WHERE id = UUID_TO_BIN(:operationId) AND kind = 'PASSWORD_LOGIN'
               AND state IN ('VERIFIED','CONFIRMED','COMPLETED')
            """;

    static final String READ_CONFIRMED_OWNER = """
            SELECT o.verified_issuer, o.verified_subject, BIN_TO_UUID(o.subject_id),
                   s.customer_id, s.status, s.customer_status_version,
                   s.customer_last_block_version, s.customer_status_checked_at
              FROM auth_operation o JOIN auth_customer s ON s.id = o.subject_id
             WHERE o.id = UUID_TO_BIN(:operationId) AND o.kind = 'PASSWORD_LOGIN'
               AND o.state IN ('CONFIRMED','COMPLETED')
            """;

    static final String REJECT_JOURNEY = """
            UPDATE auth_login_journey
               SET state = 'FAILED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId)
               AND state = 'CREDENTIAL_PROCESSING'
               AND version < 9007199254740991
            """;

    static final String REJECT_OPERATION = """
            UPDATE auth_operation
               SET state = 'REJECTED', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId)
               AND kind = 'PASSWORD_LOGIN' AND state IN ('DISPATCHED','VERIFIED')
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

    static final String RECORD_MFA_UNAVAILABLE_JOURNEY = """
            UPDATE auth_login_journey
               SET state = 'FAILED', route = :route, version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:journeyId)
               AND state = 'CREDENTIAL_PROCESSING'
               AND version < 9007199254740991
            """;

    static final String RECORD_MFA_UNAVAILABLE_OPERATION = """
            UPDATE auth_operation
               SET state = 'MFA_UNAVAILABLE', version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE id = UUID_TO_BIN(:operationId)
               AND kind = 'PASSWORD_LOGIN' AND state = 'CONFIRMED'
               AND version < 9007199254740991
            """;

    private PasswordOperationSql() { }
}
