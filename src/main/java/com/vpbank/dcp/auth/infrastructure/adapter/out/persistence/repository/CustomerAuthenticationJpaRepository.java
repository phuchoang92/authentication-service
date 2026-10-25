package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerAuthenticationJpaRepository extends JpaRepository<CustomerAuthenticationEntity, String> {

    boolean existsByUserNameIgnoreCase(String userName);

    Optional<CustomerAuthenticationEntity> findByUserNameIgnoreCase(String userName);
}
