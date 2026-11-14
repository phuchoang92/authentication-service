package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.PrimaryTrustedDeviceEntity;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

public interface PrimaryTrustedDeviceJpaRepository
        extends JpaRepository<PrimaryTrustedDeviceEntity, PrimaryTrustedDeviceEntity.Key> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<PrimaryTrustedDeviceEntity> findByKey(PrimaryTrustedDeviceEntity.Key key);
}
