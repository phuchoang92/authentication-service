package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteEvidence;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteRepository;
import com.vpbank.dcp.infrastructure.persistence.mapper.PasswordDeviceRoutePersistenceMapper;
import com.vpbank.dcp.infrastructure.persistence.repository.PasswordDeviceRoutePersistenceRepository;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/** Reads typed database projections and maps them to the core port contract. */
@Repository
public class JpaPasswordDeviceRouteAdapter implements PasswordDeviceRouteRepository {
    private final PasswordDeviceRoutePersistenceRepository repository;

    public JpaPasswordDeviceRouteAdapter(PasswordDeviceRoutePersistenceRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    @Override
    public Optional<PasswordDeviceRouteEvidence> currentRoute(UUID operationId, UUID subjectId, String appId) {
        return repository.currentRoute(operationId, subjectId, appId)
                .map(PasswordDeviceRoutePersistenceMapper::toDomain);
    }
}
