package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.core.customer.RegistrationStore;
import com.vpbank.dcp.auth.infrastructure.persistence.JdbcRegistrationStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

/** MySQL adapters. DataSource, JdbcClient and transactions come from Spring Boot. */
@Configuration(proxyBeanMethods = false)
public class PersistenceConfiguration {

    @Bean
    RegistrationStore registrationStore(JdbcClient jdbc, TransactionTemplate transactions) {
        return new JdbcRegistrationStore(jdbc, transactions);
    }
}
