package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.RegistrationEntity;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RegistrationJpaRepository extends JpaRepository<RegistrationEntity, UUID> {

    Optional<RegistrationEntity> findFirstByCustomerIdOrderByCreatedAtDescRequestIdDesc(String customerId);

    /** The one open request of a customer: OPEN_SLOT is 1 while open (generated column). */
    Optional<RegistrationEntity> findByCustomerIdAndOpenSlot(String customerId, Byte openSlot);

    /** SELECT … FOR UPDATE, for the step that must write two tables together. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RegistrationEntity r where r.requestId = :requestId")
    Optional<RegistrationEntity> lockByRequestId(@Param("requestId") UUID requestId);
}
