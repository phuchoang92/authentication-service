package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.infrastructure.persistence.projection.LoginSessionSecurityView;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class LoginSessionSecurityPersistenceRepository {
    private final JdbcClient jdbc;

    public LoginSessionSecurityPersistenceRepository(DataSource dataSource) {
        this.jdbc = JdbcClient.create(Objects.requireNonNull(dataSource, "dataSource"));
    }

    public Optional<LoginSessionSecurityView> lockCurrent(UUID customerId, UUID bindingId, String channel) {
        return jdbc.sql(LoginSessionSecuritySql.CURRENT)
                .param("customerId", customerId.toString())
                .param("bindingId", bindingId.toString())
                .param("channel", channel)
                .query(LoginSessionSecurityView.class)
                .optional();
    }
}
