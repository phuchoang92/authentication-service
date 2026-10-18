package com.vpbank.dcp.infrastructure.persistence.repository;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Statements of one trust commit; the caller owns the transaction. Columns are read by alias,
 * never by position. Times are bound as UTC wall-clock values so a non-UTC JVM stores the same.
 */
@Repository
public class TrustedDeviceActivationPersistenceRepository {
    private final JdbcClient jdbc;

    public TrustedDeviceActivationPersistenceRepository(DataSource dataSource) {
        this.jdbc = JdbcClient.create(Objects.requireNonNull(dataSource, "dataSource"));
    }

    public Optional<StoredKeyRow> storedKey(UUID bindingId, UUID customerId, String channel) {
        return jdbc.sql(TrustedDeviceActivationSql.STORED_KEY)
                .param("bindingId", bindingId.toString())
                .param("customerId", customerId.toString()).param("channel", channel)
                .query(StoredKeyRow.class).optional();
    }

    public Optional<CustomerLock> lockCustomer(UUID customerId) {
        return jdbc.sql(TrustedDeviceActivationSql.LOCK_CUSTOMER)
                .param("customerId", customerId.toString())
                .query(CustomerLock.class).optional();
    }

    public Optional<UUID> lockPrimary(UUID customerId, String channel) {
        return jdbc.sql(TrustedDeviceActivationSql.LOCK_PRIMARY)
                .param("customerId", customerId.toString()).param("channel", channel)
                .query(BindingRow.class).optional().map(BindingRow::id);
    }

    public Optional<DeviceLock> lockDevice(UUID bindingId, UUID customerId, String channel,
                                           Instant now) {
        return jdbc.sql(TrustedDeviceActivationSql.LOCK_DEVICE)
                .param("now", utc(now)).param("bindingId", bindingId.toString())
                .param("customerId", customerId.toString()).param("channel", channel)
                .query(DeviceLock.class).optional();
    }

    public Optional<UUID> lockLiveByDeviceId(UUID customerId, String channel, byte[] lookup,
                                             String lookupKeyId) {
        return jdbc.sql(TrustedDeviceActivationSql.LOCK_LIVE_BY_DEVICE_ID)
                .param("customerId", customerId.toString()).param("channel", channel)
                .param("lookup", lookup).param("lookupKeyId", lookupKeyId)
                .query(BindingRow.class).optional().map(BindingRow::id);
    }

    public boolean keepBinding(UUID bindingId, String serverKeyId, byte[] serverKeyCiphertext,
                               long expectedSecurityVersion, Instant now) {
        return jdbc.sql(TrustedDeviceActivationSql.KEEP_BINDING)
                .param("serverKeyId", serverKeyId).param("serverKeyCiphertext", serverKeyCiphertext)
                .param("now", utc(now)).param("bindingId", bindingId.toString())
                .param("expectedSecurityVersion", expectedSecurityVersion)
                .update() == 1;
    }

    public boolean markExpired(UUID bindingId) {
        return jdbc.sql(TrustedDeviceActivationSql.MARK_EXPIRED)
                .param("bindingId", bindingId.toString()).update() == 1;
    }

    public boolean revokeBySystem(UUID bindingId, String reasonCode, Instant now) {
        return jdbc.sql(TrustedDeviceActivationSql.REVOKE_BY_SYSTEM)
                .param("now", utc(now)).param("reasonCode", reasonCode)
                .param("bindingId", bindingId.toString()).update() == 1;
    }

    public long securityVersion(UUID bindingId) {
        return jdbc.sql(TrustedDeviceActivationSql.SECURITY_VERSION)
                .param("bindingId", bindingId.toString())
                .query(SecurityVersionRow.class).single().securityVersion();
    }

    public void insertDevice(NewDeviceRow row) {
        int inserted = jdbc.sql(TrustedDeviceActivationSql.INSERT_DEVICE)
                .param("bindingId", row.bindingId().toString())
                .param("customerId", row.customerId().toString())
                .param("channel", row.channel())
                .param("lookup", row.deviceIdLookup())
                .param("lookupKeyId", row.deviceIdLookupKeyId())
                .param("deviceIdCiphertext", row.deviceIdCiphertext())
                .param("deviceIdKeyId", row.deviceIdKeyId())
                .param("platform", row.platform())
                .param("label", row.label())
                .param("publicKey", row.publicKeySpki())
                .param("publicKeyHash", row.publicKeyHash())
                .param("trustMethod", row.trustMethod())
                .param("trustPolicyVersion", row.trustPolicyVersion())
                .param("now", utc(row.now()))
                .param("expiresAt", utc(row.expiresAt()))
                .param("serverKeyId", row.serverKeyId())
                .param("serverKeyCiphertext", row.serverKeyCiphertext())
                .update();
        if (inserted != 1) {
            throw new IllegalStateException("trusted device insert affected " + inserted + " rows");
        }
    }

    public void clearPrimary(UUID customerId, String channel) {
        jdbc.sql(TrustedDeviceActivationSql.CLEAR_PRIMARY)
                .param("customerId", customerId.toString()).param("channel", channel).update();
    }

    public boolean setPrimary(UUID bindingId) {
        return jdbc.sql(TrustedDeviceActivationSql.SET_PRIMARY)
                .param("bindingId", bindingId.toString()).update() == 1;
    }

    public void revokeBiometrics(UUID bindingId, Instant now) {
        jdbc.sql(TrustedDeviceActivationSql.REVOKE_BIOMETRICS)
                .param("now", utc(now)).param("bindingId", bindingId.toString()).update();
    }

    public long countLive(UUID customerId, String channel) {
        return jdbc.sql(TrustedDeviceActivationSql.COUNT_LIVE)
                .param("customerId", customerId.toString()).param("channel", channel)
                .query(Long.class).single();
    }

    public Optional<UUID> lockOldestLiveExcept(UUID customerId, String channel, UUID keep) {
        return jdbc.sql(TrustedDeviceActivationSql.LOCK_OLDEST_LIVE_EXCEPT)
                .param("customerId", customerId.toString()).param("channel", channel)
                .param("keepBindingId", keep.toString())
                .query(BindingRow.class).optional().map(BindingRow::id);
    }

    private static LocalDateTime utc(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    public record StoredKeyRow(byte[] publicKeySpki, byte[] publicKeyHash) {
        public StoredKeyRow {
            publicKeySpki = publicKeySpki.clone();
            publicKeyHash = publicKeyHash.clone();
        }

        @Override
        public byte[] publicKeySpki() {
            return publicKeySpki.clone();
        }

        @Override
        public byte[] publicKeyHash() {
            return publicKeyHash.clone();
        }
    }

    public record CustomerLock(String status, long statusVersion) { }

    public record DeviceLock(String status, boolean unexpired, long securityVersion,
                             byte[] publicKeyHash, byte[] publicKey) {
        public DeviceLock {
            publicKeyHash = publicKeyHash.clone();
            publicKey = publicKey.clone();
        }

        @Override
        public byte[] publicKeyHash() {
            return publicKeyHash.clone();
        }

        @Override
        public byte[] publicKey() {
            return publicKey.clone();
        }
    }

    record BindingRow(String bindingId) {
        UUID id() {
            return UUID.fromString(bindingId);
        }
    }

    record SecurityVersionRow(long securityVersion) { }

    public record NewDeviceRow(UUID bindingId, UUID customerId, String channel, byte[] deviceIdLookup,
                               String deviceIdLookupKeyId, byte[] deviceIdCiphertext,
                               String deviceIdKeyId, String platform, String label,
                               byte[] publicKeySpki, byte[] publicKeyHash, String trustMethod,
                               String trustPolicyVersion, Instant now, Instant expiresAt,
                               String serverKeyId, byte[] serverKeyCiphertext) {
        @Override
        public String toString() {
            return "NewDeviceRow[redacted]";
        }
    }
}
