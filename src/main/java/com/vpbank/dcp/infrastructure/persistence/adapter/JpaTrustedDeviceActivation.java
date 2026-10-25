package com.vpbank.dcp.infrastructure.persistence.adapter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustActivation;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustActivationResult;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceActivation;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceActivationUnavailableException;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdLookup;
import com.vpbank.dcp.infrastructure.persistence.codec.ProtectedDeviceId;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.infrastructure.persistence.entity.SecurityAuditEventHeader;
import com.vpbank.dcp.infrastructure.persistence.repository.SecurityAuditJpaRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceActivationPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceActivationPersistenceRepository.DeviceLock;
import com.vpbank.dcp.infrastructure.persistence.repository.TrustedDeviceActivationPersistenceRepository.NewDeviceRow;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * One SQL transaction per trust. Row lifecycles stay one-way: a binding that is replaced,
 * expired or evicted leaves the live set, and a lapsed device that is trusted again gets a new
 * row carrying its kept key. Every rejection rolls back, so nothing is half-trusted.
 */
public final class JpaTrustedDeviceActivation implements TrustedDeviceActivation {
    static final String REPLACED = "REPLACED";
    static final String DEVICE_LIMIT = "DEVICE_LIMIT";
    private static final String SYSTEM_ACTOR_TYPE = "SYSTEM";
    private static final String SYSTEM_ACTOR_ID = "authentication-service";
    private static final String CUSTOMER_ACTOR_TYPE = "CUSTOMER";

    private final TrustedDeviceActivationPersistenceRepository devices;
    private final SecurityAuditJpaRepository audit;
    private final DeviceIdCodec deviceIds;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final TrustPolicy policy;

    public JpaTrustedDeviceActivation(TrustedDeviceActivationPersistenceRepository devices,
                                      SecurityAuditJpaRepository audit, DeviceIdCodec deviceIds,
                                      TransactionTemplate transactions, Clock clock,
                                      TrustPolicy policy) {
        this.devices = Objects.requireNonNull(devices);
        this.audit = Objects.requireNonNull(audit);
        this.deviceIds = Objects.requireNonNull(deviceIds);
        this.transactions = Objects.requireNonNull(transactions);
        this.clock = Objects.requireNonNull(clock);
        this.policy = Objects.requireNonNull(policy);
    }

    @Override
    public TrustActivationResult activate(TrustActivation activation) {
        Objects.requireNonNull(activation);
        try {
            return Objects.requireNonNull(transactions.execute(
                    status -> activateLocked(activation, status)));
        } catch (DataIntegrityViolationException reused) {
            // A key already live on another binding, or a concurrent trust of this device.
            return new TrustActivationResult.Rejected();
        } catch (DataAccessException | TransactionException | IllegalStateException failure) {
            // IllegalStateException: an invariant broke mid-transaction and it was rolled back.
            throw new TrustedDeviceActivationUnavailableException(failure);
        }
    }

    private TrustActivationResult activateLocked(TrustActivation activation, TransactionStatus status) {
        UUID owner = activation.owner().value();
        String channel = activation.channel();
        var customer = devices.lockCustomer(owner).orElse(null);
        if (customer == null || !"ELIGIBLE".equals(customer.status())
                || customer.statusVersion() != activation.customerStatusVersion()) {
            return rejected(status);
        }
        Events events = new Events(activation);
        UUID previousPrimary = devices.lockPrimary(owner, channel).orElse(null);
        UUID activated;
        switch (activation.target()) {
            case TrustTarget.KnownDevice known -> {
                DeviceLock row = devices.lockDevice(known.bindingId().value(), owner, channel,
                        activation.now()).orElse(null);
                if (row == null || !known.deviceKeyThumbprint().equals(activation.deviceKeyThumbprint())
                        || !Arrays.equals(row.publicKeyHash(), known.deviceKeyThumbprint().bytes())) {
                    return rejected(status);
                }
                if ("ACTIVE".equals(row.status()) && row.unexpired()) {
                    // Trusted but not primary: same row, new Ksrv.
                    if (!devices.keepBinding(known.bindingId().value(),
                            activation.serverKey().keyId(), activation.serverKey().ciphertext(),
                            known.deviceSecurityVersion(), activation.now())) {
                        return rejected(status);
                    }
                    activated = known.bindingId().value();
                } else {
                    // Lapsed: the old row leaves the live set, a new row keeps the device key.
                    retire(known.bindingId().value(), activation);
                    activated = insertNew(activation, row.publicKey(), events);
                }
            }
            case TrustTarget.NewDevice() ->
                    activated = insertNew(activation, spki(activation), events);
        }
        if (!activated.equals(previousPrimary)) {
            devices.clearPrimary(owner, channel);
            if (previousPrimary != null) {
                // The new primary revokes the previous primary's biometric login.
                devices.revokeBiometrics(previousPrimary, activation.now());
            }
            if (!devices.setPrimary(activated)) {
                return rejected(status);
            }
            events.record(SecurityAuditEventEntity.primaryChanged(
                    events.header(CUSTOMER_ACTOR_TYPE), previousPrimary, activated));
        }
        while (devices.countLive(owner, channel) > policy.maximumActiveDevices()) {
            UUID oldest = devices.lockOldestLiveExcept(owner, channel, activated).orElse(null);
            if (oldest == null || !revokeBySystem(oldest, DEVICE_LIMIT, activation, events)) {
                return rejected(status);
            }
        }
        return new TrustActivationResult.Activated(new BindingId(activated));
    }

    /** A reinstalled App keeps its device ID but not its key: the old live row is replaced. */
    private UUID insertNew(TrustActivation activation, byte[] publicKeySpki, Events events) {
        UUID owner = activation.owner().value();
        for (DeviceIdLookup candidate : deviceIds.lookupCandidates(owner, activation.channel(),
                activation.deviceId())) {
            Optional<UUID> live = devices.lockLiveByDeviceId(owner, activation.channel(),
                    candidate.digest().bytes(), candidate.keyId());
            if (live.isPresent() && !revokeBySystem(live.get(), REPLACED, activation, events)) {
                throw new IllegalStateException("live binding could not be replaced");
            }
        }
        UUID bindingId = UUID.randomUUID();
        ProtectedDeviceId deviceId = deviceIds.protect(owner, activation.channel(), bindingId,
                activation.deviceId());
        devices.insertDevice(new NewDeviceRow(bindingId, owner, activation.channel(),
                deviceId.lookup().bytes(), deviceId.lookupKeyId(), deviceId.ciphertext(),
                deviceId.encryptionKeyId(), activation.platform(), activation.platform(),
                publicKeySpki, activation.deviceKeyThumbprint().bytes(), policy.trustMethod(),
                policy.trustPolicyVersion(), activation.now(),
                activation.now().plus(policy.trustLifetime()), activation.serverKey().keyId(),
                activation.serverKey().ciphertext()));
        events.record(SecurityAuditEventEntity.deviceTrusted(events.header(CUSTOMER_ACTOR_TYPE),
                bindingId, devices.securityVersion(bindingId),
                activation.mfaReceiptDigest().bytes()));
        return bindingId;
    }

    private void retire(UUID bindingId, TrustActivation activation) {
        if (devices.markExpired(bindingId)) {
            devices.revokeBiometrics(bindingId, activation.now());
        }
    }

    private boolean revokeBySystem(UUID bindingId, String reason, TrustActivation activation,
                                   Events events) {
        if (!devices.revokeBySystem(bindingId, reason, activation.now())) {
            return false;
        }
        devices.revokeBiometrics(bindingId, activation.now());
        events.record(SecurityAuditEventEntity.deviceRevokedBySystem(
                events.header(SYSTEM_ACTOR_TYPE), bindingId, devices.securityVersion(bindingId),
                reason));
        return true;
    }

    /** The presented JWK must be the key whose thumbprint the session pinned. */
    private static byte[] spki(TrustActivation activation) {
        try {
            ECKey key = ECKey.parse(activation.devicePublicJwk());
            if (key.isPrivate() || !Curve.P_256.equals(key.getCurve())
                    || !Digest32.fromBytes(key.computeThumbprint().decode())
                            .equals(activation.deviceKeyThumbprint())) {
                throw new IllegalStateException("device key does not match its thumbprint");
            }
            return key.toECPublicKey().getEncoded();
        } catch (ParseException | JOSEException failure) {
            throw new IllegalStateException("device key is not a public P-256 JWK", failure);
        }
    }

    private static TrustActivationResult rejected(TransactionStatus status) {
        status.setRollbackOnly();
        return new TrustActivationResult.Rejected();
    }

    /** Audit events of one trust share its operation ID and are numbered in commit order. */
    private final class Events {
        private final TrustActivation activation;
        private int sequence;

        private Events(TrustActivation activation) {
            this.activation = activation;
        }

        SecurityAuditEventHeader header(String actorType) {
            String actorId = SYSTEM_ACTOR_TYPE.equals(actorType) ? SYSTEM_ACTOR_ID
                    : activation.owner().value().toString();
            return new SecurityAuditEventHeader(UUID.randomUUID(), activation.owner().value(),
                    activation.channel(), activation.operationId(), ++sequence, actorType, actorId,
                    activation.now(), clock.instant());
        }

        void record(SecurityAuditEventEntity event) {
            audit.saveAndFlush(event);
        }
    }

    /** Plain policy values from validated configuration. */
    public record TrustPolicy(Duration trustLifetime, int maximumActiveDevices, String trustMethod,
                              String trustPolicyVersion) {
        public TrustPolicy {
            Objects.requireNonNull(trustLifetime, "trustLifetime");
            Objects.requireNonNull(trustMethod, "trustMethod");
            Objects.requireNonNull(trustPolicyVersion, "trustPolicyVersion");
            if (trustLifetime.isNegative() || trustLifetime.isZero()
                    || trustLifetime.compareTo(Duration.ofDays(90)) > 0
                    || maximumActiveDevices < 1 || maximumActiveDevices > 20
                    || trustMethod.isBlank() || trustMethod.length() > 40
                    || trustPolicyVersion.isBlank() || trustPolicyVersion.length() > 64) {
                throw new IllegalArgumentException("invalid trust policy");
            }
        }
    }
}
