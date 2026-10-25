package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.TrustedDeviceAuditEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrustedDeviceAuditJpaRepository extends JpaRepository<TrustedDeviceAuditEntity, UUID> {

    List<TrustedDeviceAuditEntity> findByCorrelationIdOrderByEventSequenceAsc(String correlationId);
}
