package com.vpbank.dcp.infrastructure.adapter.out.persistence.password;

import com.vpbank.dcp.core.port.out.password.PasswordDeviceKeyRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.password.PasswordDeviceKeyPersistenceRepository;

/** Delegates SQL binding and mapping to the persistence repository. */
@Repository
public class JpaPasswordDeviceKeyAdapter implements PasswordDeviceKeyRepository {
    private final PasswordDeviceKeyPersistenceRepository repository;

    public JpaPasswordDeviceKeyAdapter(PasswordDeviceKeyPersistenceRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    @Override
    public Optional<StoredDeviceKey> findActive(PasswordOperationContext operation) {
        return repository.findActive(operation);
    }
}
