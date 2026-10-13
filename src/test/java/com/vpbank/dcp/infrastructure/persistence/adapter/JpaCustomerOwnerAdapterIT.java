package com.vpbank.dcp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerOwnerPolicy;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.CustomerOwnerPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(classes = JpaCustomerOwnerAdapterIT.TestConfiguration.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.jpa.hibernate.ddl-auto=none", "spring.datasource.hikari.maximum-pool-size=5",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=1", "spring.data.redis.username=none",
        "spring.data.redis.password=none", "spring.data.redis.ssl.enabled=false"
})
class JpaCustomerOwnerAdapterIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(DockerImageName.parse(
            "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_customer_owner")
            .withUsername("auth_test").withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired CustomerOwnerRepository customers;
    @Autowired JdbcTemplate jdbc;

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EntityScan(basePackageClasses = SecurityAuditEventEntity.class)
    @EnableJpaRepositories(basePackageClasses = SecurityAuditJpaRepository.class)
    @Import(CustomerOwnerPersistenceRepository.class)
    static class TestConfiguration {
        @Bean
        TransactionTemplate transactionTemplate(PlatformTransactionManager manager) {
            return new TransactionTemplate(manager);
        }

        @Bean
        CustomerOwnerRepository customerOwnerRepository(CustomerOwnerPersistenceRepository repository,
                                                        TransactionTemplate transactions) {
            return new JpaCustomerOwnerAdapter(repository, new CustomerOwnerPolicy(), transactions);
        }
    }

    @Test
    void verifiedIdentityCreatesAndRefreshesOneCustomer() {
        String customerId = "customer-" + UUID.randomUUID();
        VerifiedProviderIdentity identity = new VerifiedProviderIdentity("https://keycloak.test/realms/bank", "subject-" + UUID.randomUUID());
        Instant firstCheck = Instant.parse("2026-10-13T07:00:00Z");
        CustomerAuthenticationState first = new CustomerAuthenticationState(customerId,
                CustomerStatus.ELIGIBLE, 1, 0, firstCheck);

        CustomerOwnerAcceptance created = customers.accept(identity, first, "test-policy");
        assertThat(created).isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        UUID storedId = ((CustomerOwnerAcceptance.Accepted) created).subjectId();
        CustomerAuthenticationState newer = new CustomerAuthenticationState(customerId,
                CustomerStatus.ELIGIBLE, 2, 0, firstCheck.plusSeconds(30));
        assertThat(customers.accept(identity, newer, "test-policy"))
                .isEqualTo(new CustomerOwnerAcceptance.Accepted(storedId));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_customer WHERE customer_id = ?",
                Integer.class, customerId)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT customer_status_version FROM auth_customer WHERE customer_id = ?",
                Long.class, customerId)).isEqualTo(2L);
    }

    @Test
    void differentVerifiedIdentityCannotClaimExistingCustomer() {
        String customerId = "customer-" + UUID.randomUUID();
        CustomerAuthenticationState snapshot = new CustomerAuthenticationState(customerId,
                CustomerStatus.ELIGIBLE, 1, 0, Instant.parse("2026-10-13T07:00:00Z"));
        customers.accept(new VerifiedProviderIdentity("https://keycloak.test/realms/bank", "owner"), snapshot, "test-policy");

        assertThat(customers.accept(new VerifiedProviderIdentity("https://keycloak.test/realms/bank", "intruder"),
                snapshot, "test-policy")).isInstanceOf(CustomerOwnerAcceptance.Rejected.class);
    }
}
