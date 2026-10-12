package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.infrastructure.persistence.mapper.PasswordDeviceKeyPersistenceMapper;
import com.vpbank.dcp.infrastructure.persistence.repository.PasswordDeviceKeyPersistenceRepository;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Reads typed database projections and maps them to the core port contract. */
@Repository
public class JpaPasswordDeviceKeyAdapter implements PasswordDeviceKeyRepository {
    private final PasswordDeviceKeyPersistenceRepository repository;

    public JpaPasswordDeviceKeyAdapter(PasswordDeviceKeyPersistenceRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    @Override
    public Optional<StoredDeviceKey> findActive(PasswordOperationContext operation) {
        return repository.findActive(operation).map(PasswordDeviceKeyPersistenceMapper::toDomain);
    }
}
