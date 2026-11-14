package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.ConfirmTrustCommand;
import com.vpbank.dcp.auth.application.command.RouteAfterPasswordCommand;
import com.vpbank.dcp.auth.application.port.out.model.TrustConfirmation;
import com.vpbank.dcp.auth.application.port.out.repository.TrustedDeviceRepository;
import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.application.result.KnownDeviceSummary;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.PrimaryMode;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DeviceInstallation;
import com.vpbank.dcp.auth.domain.model.DeviceKey;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.NewDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
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
    @NonNull
    private final TrustedDeviceRepository trustedDeviceRepository;
    @NonNull
    private final DevicePolicy devicePolicy;
    @NonNull
    private final Supplier<TrustedDeviceId> trustedDeviceIdGenerator;
    @NonNull
    private final Clock clock;

    /**
     * What the login may issue after a correct password.
     */
    public sealed interface DeviceRouting {
        /**
         * Trusted primary device, or a channel without device trust: a full ACTIVE session.
         */
        record FullSession() implements DeviceRouting {
        }

        /**
         * New, not primary, expired, only registered or key not proven: a restricted NEED_TRUSTED_DEVICE session.
         */
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
        Optional<TrustedDevice> trustedPrimary = findTrustedPrimary(installation, now);
        if (trustedPrimary.isEmpty()) {
            return new DeviceRouting.NeedTrust();
        }

        // The row's key is what trust means: a login that cannot prove it is not this installation.
        TrustedDevice primaryDevice = trustedPrimary.get();
        if (!possession.provenFor(primaryDevice)) {
            return new DeviceRouting.NeedTrust();
        }

        // Login metadata is not a second admission decision; a stale snapshot does not overwrite the row.
        trustedDeviceRepository.recordLoginIfCurrent(primaryDevice.id(), primaryDevice.version(), now);
        return new DeviceRouting.FullSession();
    }

    /**
     * What another service may know about a live installation (never the aggregate).
     */
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
     * Empty when this enrollment was committed already, or a racing commit got there first: nothing is written.
     */
    public Optional<TrustedDevice> confirmTrust(@NonNull ConfirmTrustCommand command) {
        DeviceEnrollment enrollment = command.enrollment();
        TrustedDevice candidate = newTrustedBinding(enrollment, command.deviceKey());

        TrustConfirmation trustConfirmation = TrustConfirmation.builder()
                .device(candidate)
                .enrollment(enrollment.complete())
                .primaryMode(PrimaryMode.FACE_CONFIRMED)
                .faceAuthenticated(true)
                .receiptDigest(command.receiptDigest())
                .creationSessionId(command.restrictedSessionId())
                .build();
        return trustedDeviceRepository.trustConfirmed(trustConfirmation, command.correlationId());
    }

    /**
     * The new row for the installation, trusted now with the key the enrollment proved.
     */
    private TrustedDevice newTrustedBinding(DeviceEnrollment enrollment, DeviceKey deviceKey) {
        NewDevice newDevice = NewDevice.builder()
                .id(trustedDeviceIdGenerator.get())
                .installation(enrollment.requester())
                .key(deviceKey)
                .createdAt(clock.instant())
                .build();
        return TrustedDevice.trustedByEnrollment(newDevice, devicePolicy);
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
        return trustedDeviceRepository.findLivePrimary(installation)
                .filter(device -> device.isTrusted(now));
    }

    /**
     * The claim trusts the candidate key the enrollment pinned. The commit checks the original target
     * and approver against the locked rows.
     */
    public Optional<TrustedDevice> confirmTrustByApproval(@NonNull DeviceEnrollment consumedEnrollment,
                                                          @NonNull String correlationId) {
        DeviceKey candidateKey = consumedEnrollment.candidateKey();
        if (candidateKey == null) {
            return Optional.empty();
        }
        TrustedDevice candidate = newTrustedBinding(consumedEnrollment, candidateKey);

        TrustConfirmation trustConfirmation = TrustConfirmation.builder()
                .device(candidate)
                .enrollment(consumedEnrollment)
                .primaryMode(PrimaryMode.OLD_DEVICE_APPROVAL)
                .faceAuthenticated(false)
                .actorDeviceId(consumedEnrollment.actorDeviceId())
                .build();
        return trustedDeviceRepository.trustConfirmed(trustConfirmation, correlationId);
    }

    /**
     * The customer's live devices on the channel, with the primary flagged; display data for the device list.
     */
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

}
