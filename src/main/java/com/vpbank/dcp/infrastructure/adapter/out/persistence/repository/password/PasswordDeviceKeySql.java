package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

final class PasswordDeviceKeySql {

    static final String FIND_ACTIVE = """
            SELECT k.public_key_spki, k.jkt
              FROM auth_device_binding b
              JOIN auth_device_key k ON k.binding_id = b.id
               AND k.subject_id = b.subject_id AND k.app_id = b.app_id
             WHERE b.id = UUID_TO_BIN(:bindingId)
               AND b.app_id = :appId
               AND b.installation_hash = :installationHash
               AND b.status = 'ACTIVE' AND b.expires_at > UTC_TIMESTAMP(6)
               AND k.purpose = 'DEVICE_POSSESSION' AND k.status = 'ACTIVE'
               AND k.algorithm = 'ES256' AND k.expires_at > UTC_TIMESTAMP(6)
            """;

    private PasswordDeviceKeySql() { }
}
