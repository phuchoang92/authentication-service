package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.SecurityAuditEventEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityAuditEventJpaRepository extends JpaRepository<SecurityAuditEventEntity, UUID> {

    /** A customer's timeline (IX_SAE_CUSTOMER_TIME). */
    List<SecurityAuditEventEntity> findByCustomerIdOrderByOccurredAtAscIdAsc(String customerId);
}
