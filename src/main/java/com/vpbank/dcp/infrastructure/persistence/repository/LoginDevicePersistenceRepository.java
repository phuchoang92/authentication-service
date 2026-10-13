package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.infrastructure.persistence.projection.LoginDeviceKeyView;
import com.vpbank.dcp.infrastructure.persistence.projection.LoginDeviceView;
import jakarta.persistence.EntityManager;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public class LoginDevicePersistenceRepository {
    private final EntityManager entityManager;

    public LoginDevicePersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager);
    }

    public Optional<LoginDeviceKeyView> keyForProof(UUID bindingId) {
        List<?> rows = entityManager.createNativeQuery(LoginDeviceSql.KEY_FOR_PROOF)
                .setParameter("bindingId", bindingId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        Object[] row = (Object[]) onlyRow(rows);
        return Optional.of(new LoginDeviceKeyView((byte[]) row[0], (byte[]) row[1]));
    }

    public Optional<LoginDeviceView> lockCurrent(UUID customerId, String channel, UUID bindingId) {
        List<?> rows = entityManager.createNativeQuery(LoginDeviceSql.CURRENT)
                .setParameter("customerId", customerId.toString())
                .setParameter("channel", channel)
                .setParameter("bindingId", bindingId.toString()).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        Object[] row = (Object[]) onlyRow(rows);
        return Optional.of(new LoginDeviceView(UUID.fromString((String) row[0]),
                UUID.fromString((String) row[1]), (String) row[2], (String) row[3],
                (byte[]) row[4], (String) row[5], (String) row[6],
                ((Number) row[7]).intValue() == 1,
                ((LocalDateTime) row[8]).toInstant(ZoneOffset.UTC),
                ((Number) row[9]).longValue(), (byte[]) row[10], (byte[]) row[11]));
    }

    private Object onlyRow(List<?> rows) {
        if (rows.size() != 1) {
            throw new UnexpectedLoginDeviceStateException();
        }
        return rows.getFirst();
    }
}
