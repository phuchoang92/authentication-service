package com.vpbank.dcp.auth.config;

import com.vpbank.dcp.auth.adapter.out.persistence.adapter.RegistrationPersistenceAdapter;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import com.vpbank.dcp.auth.adapter.out.persistence.repository.RegistrationJpaRepository;
import com.vpbank.dcp.auth.application.port.out.RegistrationRepository;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * MySQL through Spring Data JPA. Entities and repositories are picked up from their role
 * packages only; a new table is registered by adding its types there, nothing else. Adapters
 * are typed by their port so the {@code @Transactional} proxy is interface-based.
 */
@Configuration(proxyBeanMethods = false)
@EntityScan(basePackages = "com.vpbank.dcp.auth.adapter.out.persistence.entity")
@EnableJpaRepositories(basePackages = "com.vpbank.dcp.auth.adapter.out.persistence.repository")
public class JpaConfiguration {

    @Bean
    RegistrationRepository registrationRepository(RegistrationJpaRepository registrations,
                                                  CustomerAuthenticationJpaRepository identities) {
        return new RegistrationPersistenceAdapter(registrations, identities);
    }
}
