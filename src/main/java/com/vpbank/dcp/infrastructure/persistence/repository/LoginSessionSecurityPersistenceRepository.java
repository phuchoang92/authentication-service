package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.infrastructure.persistence.projection.LoginSessionSecurityView;
import jakarta.persistence.EntityManager;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class LoginSessionSecurityPersistenceRepository {
    private final EntityManager entityManager;

    public LoginSessionSecurityPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager);
    }

    public Optional<LoginSessionSecurityView> lockCurrent(UUID customerId, UUID bindingId, String channel) {
        List<?> rows = entityManager.createNativeQuery(LoginSessionSecuritySql.CURRENT)
                .setParameter("customerId", customerId.toString())
                .setParameter("bindingId", bindingId.toString())
                .setParameter("channel", channel).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedLoginDeviceStateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new LoginSessionSecurityView((String) row[0],
                ((Number) row[1]).longValue(), ((Number) row[2]).longValue(),
                ((Number) row[3]).longValue(), (String) row[4],
                ((Number) row[5]).intValue() == 1,
                ((LocalDateTime) row[6]).toInstant(ZoneOffset.UTC),
                ((Number) row[7]).longValue(),
                ((Number) row[8]).intValue() == 1));
    }
}
