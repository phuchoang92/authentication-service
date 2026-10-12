package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

final class PasswordDeviceRouteSql {

    static final String CURRENT_ROUTE = """
            SELECT BIN_TO_UUID(j.candidate_binding_id),
                   BIN_TO_UUID(a.last_successful_binding_id),
                   j.installation_hash, j.device_proof_jkt,
                   BIN_TO_UUID(b.id), BIN_TO_UUID(b.subject_id), b.app_id,
                   b.installation_hash, b.status, b.expires_at,
                   k.status, k.expires_at > UTC_TIMESTAMP(6), k.jkt
              FROM auth_operation o
              JOIN auth_login_journey j ON j.id = o.journey_id
              JOIN auth_subject_app a ON a.subject_id = o.subject_id
                                     AND a.app_id = o.app_id
              LEFT JOIN auth_device_binding b ON b.id = j.candidate_binding_id
              LEFT JOIN auth_device_key k ON k.binding_id = b.id
                                         AND k.purpose = 'DEVICE_POSSESSION'
                                         AND k.status = 'ACTIVE'
             WHERE o.id = UUID_TO_BIN(:operationId)
               AND o.subject_id = UUID_TO_BIN(:subjectId)
               AND o.app_id = :appId
               AND o.kind = 'PASSWORD_LOGIN' AND o.state IN ('CONFIRMED','COMPLETED')
               AND j.subject_id = o.subject_id AND j.app_id = o.app_id
               AND a.status = 'ACTIVE'
            """;

    private PasswordDeviceRouteSql() { }
}
