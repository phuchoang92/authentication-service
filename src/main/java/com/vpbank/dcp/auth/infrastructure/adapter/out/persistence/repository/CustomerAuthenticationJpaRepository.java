package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

public interface CustomerAuthenticationJpaRepository extends JpaRepository<CustomerAuthenticationEntity, String> {

    boolean existsByUserNameIgnoreCase(String userName);

    /** The column's case-insensitive collation lets this equality use the username unique index. */
    Optional<CustomerAuthenticationEntity> findByUserName(String userName);

    /** Shared owner lock for approval reservation, trust commit and binding removal. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CustomerAuthenticationEntity> findByCustomerId(String customerId);
}
