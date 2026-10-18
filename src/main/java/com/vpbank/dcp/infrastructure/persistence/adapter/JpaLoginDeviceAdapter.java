package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.device.LoginDeviceUnavailableException;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdLookup;
import com.vpbank.dcp.infrastructure.id.OpaqueBindingIdCodec;
import com.vpbank.dcp.infrastructure.persistence.projection.LoginDeviceView;
import com.vpbank.dcp.infrastructure.persistence.repository.LoginDevicePersistenceRepository;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

public final class JpaLoginDeviceAdapter implements LoginDeviceRepository {
    private final LoginDevicePersistenceRepository devices;
    private final DeviceIdCodec deviceIds;
    private final OpaqueBindingIdCodec publicIds;
    private final TransactionTemplate transactions;

    public JpaLoginDeviceAdapter(LoginDevicePersistenceRepository devices, DeviceIdCodec deviceIds,
                                 OpaqueBindingIdCodec publicIds, TransactionTemplate transactions) {
        this.devices = Objects.requireNonNull(devices);
        this.deviceIds = Objects.requireNonNull(deviceIds);
        this.publicIds = Objects.requireNonNull(publicIds);
        this.transactions = Objects.requireNonNull(transactions);
    }

    @Override
    public Optional<StoredDeviceKey> keyForProof(String publicBindingId) {
        try {
            return publicIds.decode(publicBindingId).flatMap(devices::keyForProof)
                    .map(key -> new StoredDeviceKey(key.publicKey(),
                            com.vpbank.dcp.core.domain.security.Digest32.fromBytes(key.thumbprint())));
        } catch (DataAccessException | TransactionException failure) {
            throw new LoginDeviceUnavailableException(failure);
        }
    }

    @Override
    public Optional<LoginDeviceSnapshot> current(SubjectId owner, String channel,
                                                 String deviceId, String publicBindingId) {
        Optional<UUID> bindingId = publicIds.decode(publicBindingId);
        if (bindingId.isEmpty()) {
            return Optional.empty();
        }
        return currentByBinding(owner, channel, deviceId, new BindingId(bindingId.get()));
    }

    @Override
    public Optional<LoginDeviceSnapshot> currentByBinding(SubjectId owner, String channel,
                                                           String deviceId, BindingId bindingId) {
        try {
            return Objects.requireNonNull(transactions.execute(ignored -> devices.lockCurrent(
                    owner.value(), channel, bindingId.value()).map(device -> toSnapshot(device, deviceId))));
        } catch (DataAccessException | TransactionException failure) {
            throw new LoginDeviceUnavailableException(failure);
        }
    }

    private LoginDeviceSnapshot toSnapshot(LoginDeviceView device, String deviceId) {
        boolean matches = false;
        for (DeviceIdLookup candidate : deviceIds.lookupCandidates(
                device.customerId(), device.channel(), deviceId)) {
            if (candidate.keyId().equals(device.deviceIdLookupKeyId())
                    && MessageDigest.isEqual(candidate.digest().bytes(), device.deviceIdLookup())) {
                matches = true;
            }
        }
        return new LoginDeviceSnapshot(new BindingId(device.bindingId()), new SubjectId(device.customerId()), device.channel(),
                device.platform(), matches, "ACTIVE".equals(device.status()), device.primary(),
                device.expiresAt(), device.securityVersion(), new StoredDeviceKey(
                device.publicKey(), com.vpbank.dcp.core.domain.security.Digest32.fromBytes(
                        device.publicKeyHash())));
    }
}
