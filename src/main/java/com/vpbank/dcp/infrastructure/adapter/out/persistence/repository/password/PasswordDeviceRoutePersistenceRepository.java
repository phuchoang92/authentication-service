package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password;

import com.vpbank.dcp.core.domain.device.DeviceCandidate;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteEvidence;
import jakarta.persistence.EntityManager;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
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

    public Optional<PasswordDeviceRouteEvidence> currentRoute(UUID operationId,
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
        UUID claimed = uuid(row[0]);
        UUID lastSuccessful = uuid(row[1]);
        String installationHash = base64((byte[]) row[2]);
        return Optional.of(new PasswordDeviceRouteEvidence(claimed, lastSuccessful,
                installationHash, candidate(row)));
    }

    private Optional<DeviceCandidate> candidate(Object[] row) {
        if (row[4] == null) {
            return Optional.empty();
        }
        boolean currentKey = row[10] != null && row[11] != null && row[12] != null
                && row[3] != null
                && MessageDigest.isEqual((byte[]) row[3], (byte[]) row[12]);
        DeviceCandidate candidate = new DeviceCandidate(uuid(row[4]), uuid(row[5]),
                (String) row[6], base64((byte[]) row[7]), "ACTIVE".equals(row[8]),
                ((LocalDateTime) row[9]).toInstant(ZoneOffset.UTC),
                currentKey && "ACTIVE".equals(row[10])
                        && ((Number) row[11]).intValue() == 1,
                currentKey);
        return Optional.of(candidate);
    }

    private UUID uuid(Object value) {
        return value == null ? null : UUID.fromString((String) value);
    }

    private String base64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
