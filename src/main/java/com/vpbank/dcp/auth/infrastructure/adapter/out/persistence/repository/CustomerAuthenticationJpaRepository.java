package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CustomerAuthenticationJpaRepository extends JpaRepository<CustomerAuthenticationEntity, String> {

    boolean existsByUserNameIgnoreCase(String userName);

    Optional<CustomerAuthenticationEntity> findByUserNameIgnoreCase(String userName);
}
