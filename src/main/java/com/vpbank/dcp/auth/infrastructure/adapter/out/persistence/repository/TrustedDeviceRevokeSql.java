package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

final class TrustedDeviceRevokeSql {
    private TrustedDeviceRevokeSql() {
    }

    static final String SNAPSHOT_BINDING = """
            INSERT INTO TRUSTED_DEVICE_REVOKE (
                ID, CUSTOMER_ID, CHANNEL, CLIENT_DEVICE_ID_LOOKUP, CLIENT_DEVICE_ID_LOOKUP_KEY_ID,
                CLIENT_DEVICE_ID_CIPHERTEXT, CLIENT_DEVICE_ID_KEY_ID, PLATFORM, STATUS, TRUST_LEVEL,
                TRUSTED_AT, EXPIRES_AT, LAST_SUCCESSFUL_LOGIN_AT, PRIMARY_CRYPTO_SUITE, PRIMARY_PUBLIC_KEY,
                PRIMARY_KEY_ID, VERSION, CREATED_AT, UPDATED_AT
            )
            SELECT ID, CUSTOMER_ID, CHANNEL, CLIENT_DEVICE_ID_LOOKUP, CLIENT_DEVICE_ID_LOOKUP_KEY_ID,
                   CLIENT_DEVICE_ID_CIPHERTEXT, CLIENT_DEVICE_ID_KEY_ID, PLATFORM, 'REVOKED', TRUST_LEVEL,
                   TRUSTED_AT, EXPIRES_AT, LAST_SUCCESSFUL_LOGIN_AT, PRIMARY_CRYPTO_SUITE, PRIMARY_PUBLIC_KEY,
                   PRIMARY_KEY_ID, VERSION, CREATED_AT, UPDATED_AT
            FROM TRUSTED_DEVICE
            WHERE ID = :id AND CUSTOMER_ID = :customerId AND CHANNEL = :channel AND VERSION = :version
            """;

    static final String COUNT_OWNED_SNAPSHOT = """
            SELECT COUNT(*)
            FROM TRUSTED_DEVICE_REVOKE
            WHERE ID = :id AND CUSTOMER_ID = :customerId AND CHANNEL = :channel
            """;
}
