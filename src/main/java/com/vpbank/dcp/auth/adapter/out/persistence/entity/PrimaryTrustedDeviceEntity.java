package com.vpbank.dcp.auth.adapter.out.persistence.entity;

import com.vpbank.dcp.auth.adapter.out.persistence.common.AuditedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

/** Row of PRIMARY_TRUSTED_DEVICE: at most one primary per customer + channel (the primary key is the rule). */
@Entity
@Table(name = "PRIMARY_TRUSTED_DEVICE")
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class PrimaryTrustedDeviceEntity extends AuditedEntity {

    @EmbeddedId
    private Key key;

    @Column(name = "PRIMARY_DEVICE_ID", columnDefinition = "BINARY(16)")
    private UUID primaryDeviceId;

    @Column(name = "ASSIGNED_AT")
    private Instant assignedAt;

    @Version
    @Column(name = "AUTHORITY_VERSION", nullable = false)
    private long authorityVersion;

    /** Composite key. JPA needs value equality on an embedded ID, written out so no proxy surprises hide in it. */
    @Embeddable
    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @AllArgsConstructor
    public static class Key implements Serializable {
        @Column(name = "CUSTOMER_ID", length = 16, nullable = false)
        private String customerId;

        @Column(name = "CHANNEL", length = 64, nullable = false)
        private String channel;

        @Override
        public boolean equals(Object other) {
            return other instanceof Key key && customerId.equals(key.customerId) && channel.equals(key.channel);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(customerId, channel);
        }
    }
}
