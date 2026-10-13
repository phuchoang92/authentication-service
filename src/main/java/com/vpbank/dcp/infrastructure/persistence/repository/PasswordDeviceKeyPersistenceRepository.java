package com.vpbank.dcp.infrastructure.persistence.repository;

import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.infrastructure.persistence.projection.StoredDeviceKeyView;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Tuple;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Looks up only an active Kdev. It does not decide customer ownership. */
@Repository
public class PasswordDeviceKeyPersistenceRepository {

    private final EntityManager entityManager;

    public PasswordDeviceKeyPersistenceRepository(EntityManager entityManager) {
        this.entityManager = Objects.requireNonNull(entityManager, "entityManager");
    }

    public Optional<StoredDeviceKeyView> findActive(PasswordOperationContext operation) {
        Objects.requireNonNull(operation, "operation");
        if (operation.claimedBindingId() == null) {
            return Optional.empty();
        }
        @SuppressWarnings("unchecked")
        List<Tuple> rows = entityManager.createNativeQuery(PasswordDeviceKeySql.FIND_ACTIVE, Tuple.class)
                .setParameter("bindingId", operation.claimedBindingId().toString())
                .setParameter("appId", operation.appId())
                .setParameter("installationHash", installationHash(operation.installationId()))
                .getResultList();
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        if (rows.size() != 1) {
            throw new UnexpectedPasswordOperationUpdateException();
        }
        Tuple row = rows.getFirst();
        return Optional.of(new StoredDeviceKeyView(
                row.get("public_key_spki", byte[].class), row.get("jkt", byte[].class)));
    }

    private byte[] installationHash(String installationId) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(installationId.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }
}
