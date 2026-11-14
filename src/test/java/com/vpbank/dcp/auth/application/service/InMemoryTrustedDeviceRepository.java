package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Device rows with the adapter's contract: one live row per installation, one primary per customer + channel, CAS. */
final class InMemoryTrustedDeviceRepository implements TrustedDeviceRepository {
    record Key(CustomerId customerId, Channel channel) { }

    final Map<TrustedDeviceId, TrustedDevice> rows = new HashMap<>();
    final Map<Key, TrustedDeviceId> primaries = new HashMap<>();
    final List<String> audit = new ArrayList<>();
    /** Enrollments whose trust is committed: a second commit of either path writes nothing. */
    final Set<EnrollmentId> committedEnrollments = new HashSet<>();
    /** Runs right after a commit, to let a test change the world between the commit and what follows it. */
    Runnable afterTrustConfirmed = () -> { };
    boolean unavailable;

    @Override
    public Optional<TrustedDevice> findLive(CustomerId customerId, Channel channel, DeviceId deviceId) {
        return findLive(customerId, channel).stream().filter(d -> d.deviceId().equals(deviceId)).findFirst();
    }

    @Override
    public List<TrustedDevice> findLive(CustomerId customerId, Channel channel) {
        check();
        return rows.values().stream().filter(d -> d.customerId().equals(customerId) && d.channel() == channel).toList();
    }

    @Override
    public Optional<TrustedDeviceId> findPrimary(CustomerId customerId, Channel channel) {
        check();
        return Optional.ofNullable(primaries.get(new Key(customerId, channel)));
    }

    @Override
    public Optional<TrustedDevice> findLivePrimary(DeviceInstallation installation) {
        return findPrimary(installation.customerId(), installation.channel())
                .map(rows::get)
                .filter(device -> device.customerId().equals(installation.customerId())
                        && device.channel() == installation.channel()
                        && device.deviceId().equals(installation.deviceId()));
    }

    @Override
    public boolean recordLoginIfCurrent(TrustedDeviceId trustedDeviceId, long expectedVersion, Instant loggedInAt) {
        check();
        TrustedDevice currentDevice = rows.get(trustedDeviceId);
        if (currentDevice == null || currentDevice.version() != expectedVersion || !currentDevice.isTrusted(loggedInAt)) {
            return false;
        }
        if (currentDevice.lastLoginAt() != null && !loggedInAt.isAfter(currentDevice.lastLoginAt())) {
            return false;
        }
        TrustedDevice updatedDevice = currentDevice.recordLogin(loggedInAt);
        rows.put(trustedDeviceId, updatedDevice.toBuilder().version(expectedVersion + 1).build());
        return true;
    }

    final java.util.List<TrustConfirmation> confirmations = new ArrayList<>();

    @Override
    public Optional<TrustedDevice> trustConfirmed(TrustConfirmation confirmation, String correlationId) {
        check();
        if (committedEnrollments.contains(confirmation.enrollment().id())) {
            return Optional.empty();
        }
        TrustedDevice candidate = confirmation.device();
        Optional<TrustedDevice> current = findLive(candidate.customerId(), candidate.channel(), candidate.deviceId());
        if (!Objects.equals(current.map(TrustedDevice::id).orElse(null), confirmation.enrollment().targetDeviceId())) {
            return Optional.empty();
        }
        Key owner = new Key(candidate.customerId(), candidate.channel());
        if (confirmation.enrollment().isApproval()
                && !Objects.equals(primaries.get(owner), confirmation.enrollment().actorDeviceId())) {
            return Optional.empty();
        }
        List<TrustedDevice> peers = findLive(candidate.customerId(), candidate.channel()).stream()
                .filter(binding -> !binding.deviceId().equals(candidate.deviceId())).toList();
        DevicePolicy policy = DevicePolicy.standard();
        policy.bindingsBeyondCap(peers).forEach(binding -> rows.remove(binding.id()));
        TrustedDevice confirmed = current.filter(binding -> confirmation.enrollment().isApproval()
                        && !binding.hasExpired(candidate.trustedAt())
                        && Objects.equals(binding.publicKey(), candidate.publicKey()))
                .map(binding -> binding.trustByApproval(candidate.trustedAt(), policy))
                .orElse(candidate);
        current.ifPresent(binding -> rows.remove(binding.id()));
        rows.put(confirmed.id(), confirmed);
        primaries.put(owner, confirmed.id());
        committedEnrollments.add(confirmation.enrollment().id());
        confirmations.add(confirmation);
        audit.add(correlationId + ":DEVICE_TRUSTED:" + confirmation.enrollment().id());
        afterTrustConfirmed.run();
        return Optional.of(confirmed);
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
