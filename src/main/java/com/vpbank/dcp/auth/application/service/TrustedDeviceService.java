package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ConfirmTrustCommand;
import com.vpbank.dcp.auth.application.command.RegisterPendingDeviceCommand;
import com.vpbank.dcp.auth.application.command.RouteAfterPasswordCommand;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository.RegisterPendingResult;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.exception.DeviceStateException;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.EnrollmentPolicy;
import com.vpbank.dcp.auth.domain.model.NewDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Owns the device rules (ARCHITECTURE §6.1): which installation is trusted, which is primary, and
 * whether a login proved the trusted key. {@link LoginService} calls it after the password is
 * verified and decides the session from the answer; it never touches device rows itself. Trust is
 * only ever granted by the enrollment and approval flows, never by a login (slice 13).
 */
@RequiredArgsConstructor
public final class TrustedDeviceService {
    /** Devices that never logged in sort as the oldest when the cap chooses what to expire. */
    private static final Comparator<TrustedDevice> OLDEST_LOGIN_FIRST =
            Comparator.comparing(device -> device.lastLoginAt() == null ? Instant.EPOCH : device.lastLoginAt());

    @NonNull private final TrustedDeviceRepository trustedDeviceRepository;
    @NonNull private final DevicePolicy devicePolicy;
    @NonNull private final Supplier<TrustedDeviceId> trustedDeviceIdGenerator;
    @NonNull private final Clock clock;

    /** What the login may issue after a correct password. */
    public sealed interface DeviceRouting {
        /** Trusted primary device, or a channel without device trust: a full ACTIVE session. */
        record FullSession() implements DeviceRouting {
        }

        /** New, not primary, expired, only registered or key not proven: a restricted NEED_TRUSTED_DEVICE session. */
        record NeedTrust() implements DeviceRouting {
        }
    }

    /**
     * Whether the login proved it holds the trusted row's key (slice 13). Login supplies it; it may read the
     * replay store and throw {@code RepositoryUnavailableException}, which the login turns into "unavailable".
     */
    @FunctionalInterface
    public interface DevicePossession {
        boolean provenFor(TrustedDevice device);
    }

    /**
     * DD 20 §2: trusted? → primary? → holds the key? WEB has no device trust. A login never trusts a
     * device: a new one, a trusted one that is not primary, an expired one, and a primary device that
     * cannot prove its key (a reinstalled app, or a copied device ID) all wait for the trust flow.
     */
    public DeviceRouting routeAfterPassword(@NonNull RouteAfterPasswordCommand command,
                                            @NonNull DevicePossession possession) {
        if (command.channel() != Channel.MOBILE) {
            return new DeviceRouting.FullSession();
        }
        Instant now = clock.instant();
        DeviceInstallation installation =
                new DeviceInstallation(command.customerId(), command.channel(), command.deviceId());
        Optional<TrustedDevice> primaryDevice = findTrustedPrimary(installation, now);
        if (primaryDevice.isEmpty()) {
            return new DeviceRouting.NeedTrust();
        }

        // The row's key is what trust means: a login that cannot prove it is not this installation.
        if (!possession.provenFor(primaryDevice.get())) {
            return new DeviceRouting.NeedTrust();
        }

        // Display data only: a lost race against another login is harmless.
        TrustedDevice deviceWithLogin = primaryDevice.get().recordLogin(now);
        trustedDeviceRepository.saveIfCurrent(deviceWithLogin, command.correlationId());
        return new DeviceRouting.FullSession();
    }

    /**
     * Keeps the live rows within {@code maxLiveDevices} before a new device is trusted: the oldest
     * by last login are expired (DD 20 §7). Used by the trust flows.
     */
    public List<TrustedDevice> expireBeyondCap(List<TrustedDevice> liveTrustedDevices, String correlationId) {
        List<TrustedDevice> oldestBeyondCap = oldestBeyondCap(liveTrustedDevices);

        for (TrustedDevice oldDevice : oldestBeyondCap) {
            TrustedDevice expiredDevice = oldDevice.expire();
            trustedDeviceRepository.saveIfCurrent(expiredDevice, correlationId);
        }

        return oldestBeyondCap;
    }

    /** What another service may know about a live installation (never the aggregate). */
    public Optional<KnownDeviceSummary> knownDevice(CustomerId customerId, Channel channel, DeviceId deviceId) {
        Optional<TrustedDevice> liveDevice = trustedDeviceRepository.findLive(customerId, channel, deviceId);

        return liveDevice.map(device -> new KnownDeviceSummary(
                device.id(),
                device.platform(),
                device.publicKey()));
    }

    /**
     * The enrollment flow passed FACE (DD 20 §4): this installation becomes trusted with the key it
     * proved and the customer's primary on the channel. A previous live row of the same installation
     * is replaced (a reinstall or a re-trust), the device cap is enforced, and everything is written in
     * one transaction with the enrollment and its audit trail. The old primary stays trusted (§7).
     * The enrollment row is written here for the first time (slice 11), bound to the restricted session.
     */
    public TrustedDevice confirmTrust(@NonNull ConfirmTrustCommand command) {
        DeviceEnrollment enrollment = command.enrollment();
        List<TrustedDevice> liveTrustedDevices =
                trustedDeviceRepository.findLive(enrollment.customerId(), enrollment.channel());

        Optional<TrustedDevice> replacedDevice = findByDeviceId(liveTrustedDevices, enrollment.deviceId());
        List<TrustedDevice> otherLiveDevices = new ArrayList<>(liveTrustedDevices);
        replacedDevice.ifPresent(otherLiveDevices::remove);
        List<TrustedDevice> devicesExpiredByCap = expireOldestBeyondCap(otherLiveDevices);

        TrustConfirmation trustConfirmation = TrustConfirmation.builder()
                .device(newlyTrustedDevice(command))
                .replaced(replacedDevice.map(TrustedDevice::expire).orElse(null))
                .expiredByCap(devicesExpiredByCap)
                .enrollment(enrollment.complete())
                .primaryMode(PrimaryMode.FACE_CONFIRMED)
                .faceAuthenticated(true)
                .receiptDigest(command.receiptDigest())
                .creationSessionId(command.restrictedSessionId())
                .build();
        return trustedDeviceRepository.trustConfirmed(trustConfirmation, command.correlationId());
    }

    /** The new row for the installation, trusted now with the key the enrollment proved. */
    private TrustedDevice newlyTrustedDevice(ConfirmTrustCommand command) {
        NewDevice newDevice = NewDevice.builder()
                .id(trustedDeviceIdGenerator.get())
                .installation(command.enrollment().requester())
                .key(command.deviceKey())
                .createdAt(clock.instant())
                .build();
        return TrustedDevice.trustedByEnrollment(newDevice, devicePolicy);
    }

    /**
     * Slice 6: a new installation asks to be approved by the primary device. Its public key and platform are
     * kept on a PENDING live row until the claim; a known live row of the same installation is reused as is.
     * Empty when the customer already has the maximum number of installations waiting.
     */
    public Optional<TrustedDevice> registerPendingDevice(@NonNull RegisterPendingDeviceCommand command) {
        AdmittedSession newDeviceSession = command.newDeviceSession();
        Optional<TrustedDevice> knownLiveDevice = findLiveRowOf(newDeviceSession);
        if (knownLiveDevice.isPresent()) {
            return knownLiveDevice;
        }

        EnrollmentPolicy enrollmentPolicy = command.enrollmentPolicy();
        int pendingDevices =
                trustedDeviceRepository.countPending(newDeviceSession.customerId(), newDeviceSession.channel());
        if (pendingDevices >= enrollmentPolicy.maxPendingDevices()) {
            return Optional.empty();
        }

        RegisterPendingResult registerResult =
                trustedDeviceRepository.registerPending(pendingDevice(command), command.correlationId());
        return switch (registerResult) {
            case RegisterPendingResult.Registered(TrustedDevice registeredDevice) -> Optional.of(registeredDevice);
            // another login of the same installation registered first: its row is the target
            case RegisterPendingResult.InstallationAlreadyLive() -> findLiveRowOf(newDeviceSession);
        };
    }

    /** The PENDING row of the installation, waiting as long as the approval window. */
    private TrustedDevice pendingDevice(RegisterPendingDeviceCommand command) {
        NewDevice newDevice = NewDevice.builder()
                .id(trustedDeviceIdGenerator.get())
                .installation(command.newDeviceSession().installation())
                .key(new DeviceKey(command.devicePublicJwk(), command.platform()))
                .createdAt(clock.instant())
                .build();
        return TrustedDevice.pending(newDevice, command.enrollmentPolicy().pendingWindow());
    }

    private Optional<TrustedDevice> findLiveRowOf(AdmittedSession newDeviceSession) {
        return trustedDeviceRepository.findLive(
                newDeviceSession.customerId(),
                newDeviceSession.channel(),
                newDeviceSession.deviceId());
    }

    /**
     * The device row of this session when it may act as the primary device: a full ACTIVE session (a restricted one
     * never approves) on the customer's trusted primary installation; empty otherwise.
     */
    public Optional<TrustedDeviceId> primaryDeviceIdOf(@NonNull AdmittedSession primaryDeviceSession) {
        if (!primaryDeviceSession.full()) {
            return Optional.empty();
        }
        Optional<TrustedDevice> primaryDevice =
                findTrustedPrimary(primaryDeviceSession.installation(), clock.instant());
        return primaryDevice.map(TrustedDevice::id);
    }

    /**
     * The installation's live row when it is trusted at {@code now} and the customer's primary on the channel;
     * empty for a new, only registered, expired or non-primary installation.
     */
    private Optional<TrustedDevice> findTrustedPrimary(DeviceInstallation installation, Instant now) {
        Optional<TrustedDevice> liveDevice = trustedDeviceRepository.findLive(
                installation.customerId(),
                installation.channel(),
                installation.deviceId());
        if (liveDevice.isEmpty()) {
            return Optional.empty();
        }
        TrustedDevice device = liveDevice.get();
        if (!device.isTrusted(now)) {
            return Optional.empty();
        }

        Optional<TrustedDeviceId> primaryDeviceId =
                trustedDeviceRepository.findPrimary(installation.customerId(), installation.channel());
        boolean isPrimary = primaryDeviceId.isPresent() && primaryDeviceId.get().equals(device.id());
        if (!isPrimary) {
            return Optional.empty();
        }
        return liveDevice;
    }

    /**
     * Slice 6: the primary device approved this installation and the QR token was claimed. The target row
     * (PENDING, or a known live row) becomes trusted and the customer's primary on the channel in one
     * transaction with the completed enrollment and the audit trail. The old primary stays trusted (§7).
     */
    public TrustedDevice confirmTrustByApproval(@NonNull DeviceEnrollment consumedEnrollment,
                                                @NonNull String correlationId) {
        Instant now = clock.instant();
        List<TrustedDevice> liveDevices =
                trustedDeviceRepository.findLive(consumedEnrollment.customerId(), consumedEnrollment.channel());

        TrustedDevice targetDevice = findApprovedRow(liveDevices, consumedEnrollment);
        List<TrustedDevice> otherLiveDevices = new ArrayList<>(liveDevices);
        otherLiveDevices.remove(targetDevice);
        List<TrustedDevice> devicesExpiredByCap = expireOldestBeyondCap(otherLiveDevices);

        TrustConfirmation trustConfirmation = TrustConfirmation.builder()
                .device(targetDevice.trustByApproval(now, devicePolicy))
                .replaced(null)
                .expiredByCap(devicesExpiredByCap)
                .enrollment(consumedEnrollment)
                .primaryMode(PrimaryMode.OLD_DEVICE_APPROVAL)
                .faceAuthenticated(false)
                .actorDeviceId(consumedEnrollment.actorDeviceId())
                .build();
        return trustedDeviceRepository.trustConfirmed(trustConfirmation, correlationId);
    }

    /** The row the approval targets; the request kept it live, so a missing row is a broken invariant. */
    private static TrustedDevice findApprovedRow(List<TrustedDevice> liveDevices, DeviceEnrollment consumedEnrollment) {
        return liveDevices.stream()
                .filter(device -> device.id().equals(consumedEnrollment.targetDeviceId()))
                .findFirst()
                .orElseThrow(() -> new DeviceStateException("The approved device row is no longer live"));
    }

    /** The expired copies of the rows that must go so that one more device fits under the cap. */
    private List<TrustedDevice> expireOldestBeyondCap(List<TrustedDevice> otherLiveDevices) {
        List<TrustedDevice> devicesExpiredByCap = new ArrayList<>();
        for (TrustedDevice oldDevice : oldestBeyondCap(otherLiveDevices)) {
            devicesExpiredByCap.add(oldDevice.expire());
        }
        return devicesExpiredByCap;
    }

    /** The customer's live devices on the channel, with the primary flagged; display data for the device list. */
    public List<DeviceSummary> listDevices(CustomerId customerId, Channel channel) {
        Optional<TrustedDeviceId> primaryDeviceId = trustedDeviceRepository.findPrimary(customerId, channel);
        List<TrustedDevice> liveTrustedDevices = trustedDeviceRepository.findLive(customerId, channel);

        List<DeviceSummary> summaries = new ArrayList<>();
        for (TrustedDevice device : liveTrustedDevices) {
            boolean isPrimary = primaryDeviceId.isPresent() && primaryDeviceId.get().equals(device.id());
            DeviceSummary summary = DeviceSummary.builder()
                    .deviceId(device.deviceId())
                    .platform(device.platform())
                    .status(device.status())
                    .trustLevel(device.trustLevel())
                    .primary(isPrimary)
                    .trustedAt(device.trustedAt())
                    .expiresAt(device.expiresAt())
                    .lastLoginAt(device.lastLoginAt())
                    .build();
            summaries.add(summary);
        }
        return List.copyOf(summaries);
    }

    /** The live rows that must go so that one more device fits under the cap; empty when it already fits. */
    private List<TrustedDevice> oldestBeyondCap(List<TrustedDevice> liveTrustedDevices) {
        int excessAfterNewDevice = liveTrustedDevices.size() - devicePolicy.maxLiveDevices() + 1;
        if (excessAfterNewDevice <= 0) {
            return List.of();
        }
        return liveTrustedDevices.stream()
                .sorted(OLDEST_LOGIN_FIRST)
                .limit(excessAfterNewDevice)
                .toList();
    }

    private static Optional<TrustedDevice> findByDeviceId(List<TrustedDevice> devices, DeviceId deviceId) {
        return devices.stream()
                .filter(device -> device.deviceId().equals(deviceId))
                .findFirst();
    }
}
