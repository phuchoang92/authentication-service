package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.infrastructure.persistence.entity.DeviceCredentialEntity;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

public interface DeviceCredentialJpaRepository extends Repository<DeviceCredentialEntity, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select credential from DeviceCredentialEntity credential "
            + "where credential.trustedDeviceId = :bindingId and credential.status = 'ACTIVE'")
    List<DeviceCredentialEntity> lockActive(@Param("bindingId") UUID bindingId);

    @Query("select count(credential) from DeviceCredentialEntity credential "
            + "where credential.trustedDeviceId = :bindingId and credential.status = 'ACTIVE'")
    long countActive(@Param("bindingId") UUID bindingId);

    void flush();
}
