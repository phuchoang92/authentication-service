package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PrimaryTrustedDeviceJpaRepository
        extends JpaRepository<PrimaryTrustedDeviceEntity, PrimaryTrustedDeviceEntity.Key> {
}
