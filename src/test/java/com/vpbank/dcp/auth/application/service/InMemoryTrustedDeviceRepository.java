package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Device rows with the adapter's contract: one live row per installation, one primary per customer + channel, CAS. */
final class InMemoryTrustedDeviceRepository implements TrustedDeviceRepository {
    record Key(CustomerId customerId, Channel channel) { }

    final Map<TrustedDeviceId, TrustedDevice> rows = new HashMap<>();
    final Map<Key, TrustedDeviceId> primaries = new HashMap<>();
    final List<String> audit = new ArrayList<>();
    boolean unavailable;

    @Override
    public Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId) {
        return findLive(customerId, channel).stream().filter(d -> d.deviceId().equals(deviceId)).findFirst();
    }

    @Override
    public List<TrustedDevice> findLive(CustomerId customerId, Channel channel) {
        check();
        return rows.values().stream().filter(d -> d.customerId().equals(customerId) && d.channel() == channel
                && d.status().live()).toList();
    }

    @Override
    public Optional<TrustedDeviceId> findPrimary(CustomerId customerId, Channel channel) {
        check();
        return Optional.ofNullable(primaries.get(new Key(customerId, channel)));
    }

    @Override
    public TrustFirstResult trustFirstDevice(TrustedDevice device, String correlationId) {
        check();
        Key key = new Key(device.customerId(), device.channel());
        if (primaries.containsKey(key) || findLive(device.customerId(), device.channel(), device.deviceId()).isPresent()) {
            return new TrustFirstResult.AlreadyHasDevice();
        }
        rows.put(device.id(), device);
        primaries.put(key, device.id());
        audit.add(correlationId + ":0:DEVICE_TRUSTED");
        audit.add(correlationId + ":1:PRIMARY_ASSIGNED");
        return new TrustFirstResult.Trusted(device);
    }

    final java.util.List<TrustConfirmation> confirmations = new ArrayList<>();

    @Override
    public TrustedDevice trustConfirmed(TrustConfirmation confirmation, String correlationId) {
        check();
        if (confirmation.replaced() != null) {
            rows.put(confirmation.replaced().id(), confirmation.replaced());
        }
        confirmation.expiredByCap().forEach(d -> rows.put(d.id(), d));
        rows.put(confirmation.device().id(), confirmation.device());
        primaries.put(new Key(confirmation.device().customerId(), confirmation.device().channel()), confirmation.device().id());
        confirmations.add(confirmation);
        audit.add(correlationId + ":DEVICE_TRUSTED:" + confirmation.enrollment().id());
        return confirmation.device();
    }

    @Override
    public RegisterPendingResult registerPending(TrustedDevice pendingDevice, String correlationId) {
        check();
        Optional<TrustedDevice> liveRow = findLive(pendingDevice.customerId(), pendingDevice.channel(), pendingDevice.deviceId());
        if (liveRow.isPresent()) {
            return new RegisterPendingResult.InstallationAlreadyLive();
        }
        rows.put(pendingDevice.id(), pendingDevice);
        audit.add(correlationId + ":DEVICE_REGISTERED");
        return new RegisterPendingResult.Registered(pendingDevice);
    }

    @Override
    public int countPending(CustomerId customerId, Channel channel) {
        check();
        return (int) findLive(customerId, channel).stream().filter(TrustedDevice::isPending).count();
    }

    @Override
    public Optional<TrustedDevice> saveIfCurrent(TrustedDevice changed, String correlationId) {
        check();
        TrustedDevice stored = rows.get(changed.id());
        if (stored == null || stored.version() != changed.version()) {
            return Optional.empty();
        }
        TrustedDevice saved = changed.toBuilder().version(changed.version() + 1).build();
        rows.put(changed.id(), saved);
        return Optional.of(saved);
    }

    TrustedDevice only() {
        return rows.values().iterator().next();
    }

    private void check() {
        if (unavailable) {
            throw new RepositoryUnavailableException(new RuntimeException("down"));
        }
    }
}
