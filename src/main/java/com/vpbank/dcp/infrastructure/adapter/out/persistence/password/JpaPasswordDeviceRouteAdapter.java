package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteEvidence;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteRepository;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password.PasswordDeviceRoutePersistenceRepository;

/** Delegates SQL binding and mapping to the persistence repository. */
@Repository
public class JpaPasswordDeviceRouteAdapter implements PasswordDeviceRouteRepository {
    private final PasswordDeviceRoutePersistenceRepository repository;

    public JpaPasswordDeviceRouteAdapter(PasswordDeviceRoutePersistenceRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    @Override
    public Optional<PasswordDeviceRouteEvidence> currentRoute(UUID operationId, UUID subjectId, String appId) {
        return repository.currentRoute(operationId, subjectId, appId);
    }
}
