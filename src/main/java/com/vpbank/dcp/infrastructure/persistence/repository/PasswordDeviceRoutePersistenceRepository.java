package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.infrastructure.persistence.projection.DeviceCandidateView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordDeviceRouteView;
import jakarta.persistence.EntityManager;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/** Maps current DB facts; the core decides the route and activation rechecks authority. */
@Repository
public class PasswordDeviceRoutePersistenceRepository {

    private final EntityManager entityManager;

    public PasswordDeviceRoutePersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    public Optional<PasswordDeviceRouteView> currentRoute(UUID operationId,
                                                               UUID subjectId, String appId) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(appId, "appId");
        List<?> rows = entityManager.createNativeQuery(PasswordDeviceRouteSql.CURRENT_ROUTE)
                .setParameter("operationId", operationId.toString())
                .setParameter("subjectId", subjectId.toString())
                .setParameter("appId", appId).getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Object[] row = (Object[]) rows.getFirst();
        return Optional.of(new PasswordDeviceRouteView(uuid(row[0]), uuid(row[1]),
                (byte[]) row[2], (byte[]) row[3], candidate(row)));
    }

    private DeviceCandidateView candidate(Object[] row) {
        if (row[4] == null) {
            return null;
        }
        return new DeviceCandidateView(uuid(row[4]), uuid(row[5]), (String) row[6],
                (byte[]) row[7], (String) row[8],
                ((LocalDateTime) row[9]).toInstant(ZoneOffset.UTC),
                (String) row[10], row[11] == null ? null : ((Number) row[11]).intValue(),
                (byte[]) row[12]);
    }

    private UUID uuid(Object value) {
        return value == null ? null : UUID.fromString((String) value);
    }

}
