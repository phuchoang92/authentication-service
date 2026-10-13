package com.vpbank.dcp.infrastructure.persistence.repository;

final class CustomerOwnerSql {
    static final String LOCK_BY_CUSTOMER_ID = """
            SELECT BIN_TO_UUID(id), customer_id, identity_provider_id,
                   provider_subject_id, status, customer_status_version,
                   customer_last_block_version, customer_status_checked_at, version
              FROM auth_customer
             WHERE customer_id = :customerId
             FOR UPDATE
            """;

    static final String INSERT_CUSTOMER = """
            INSERT INTO auth_customer
                (id, customer_id, identity_provider_id, provider_subject_id,
                 customer_status_version, customer_last_block_version,
                 customer_status_checked_at, status, policy_version,
                 created_at, updated_at)
            VALUES (UUID_TO_BIN(:id), :customerId, :providerId, :providerSubject,
                    :statusVersion, :blockVersion, :checkedAt, 'ELIGIBLE',
                    :policyVersion, :now, :now)
            """;

    static final String UPDATE_SNAPSHOT = """
            UPDATE auth_customer
               SET customer_status_version = :statusVersion,
                   customer_last_block_version = :blockVersion,
                   customer_status_checked_at = :checkedAt,
                   updated_at = :now,
                   version = version + 1
             WHERE id = UUID_TO_BIN(:id)
               AND version = :expectedVersion
               AND status = 'ELIGIBLE'
               AND identity_provider_id = :providerId
               AND provider_subject_id = :providerSubject
               AND customer_status_version <= :statusVersion
               AND customer_last_block_version <= :blockVersion
            """;

    private CustomerOwnerSql() {
    }
}
