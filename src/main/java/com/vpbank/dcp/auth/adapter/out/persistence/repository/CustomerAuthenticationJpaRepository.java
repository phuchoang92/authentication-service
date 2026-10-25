package com.vpbank.dcp.auth.adapter.out.persistence.repository;

import com.vpbank.dcp.auth.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerAuthenticationJpaRepository extends JpaRepository<CustomerAuthenticationEntity, String> {

    boolean existsByUserNameIgnoreCase(String userName);
}
