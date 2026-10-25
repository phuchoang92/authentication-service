package com.vpbank.dcp.auth.adapter.out.persistence.entity;

import com.vpbank.dcp.auth.adapter.out.persistence.common.AuditedEntity;
import com.vpbank.dcp.auth.domain.model.PasswordStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;

/** Row of CUSTOMER_AUTHENTICATION: the identity a customer logs in with (phase 1) and its password lockout (phase 2). */
@Entity
@Table(name = "CUSTOMER_AUTHENTICATION")
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CustomerAuthenticationEntity extends AuditedEntity {
    public static final String STATUS_ACTIVE = "ACTIVE";

    @Id
    @Column(name = "CUSTOMER_ID", length = 16, nullable = false)
    private String customerId;

    @Column(name = "USER_NAME", length = 64, nullable = false)
    private String userName;

    @Column(name = "IDENTITY_ISSUER", nullable = false)
    private String identityIssuer;

    @Column(name = "IDENTITY_SUBJECT", nullable = false)
    private String identitySubject;

    @Column(name = "STATUS", length = 16, nullable = false)
    private String status;

    @Enumerated(EnumType.STRING)
    @Column(name = "PASSWORD_STATUS", length = 24, nullable = false)
    private PasswordStatus passwordStatus;

    @Column(name = "PASSWORD_FAILED_COUNT", nullable = false)
    private int passwordFailedCount;

    @Column(name = "PASSWORD_LOCKOUT_TIME")
    private Instant passwordLockoutTime;

    @Version
    @Column(name = "VERSION", nullable = false)
    private long version;

    /** Status and lockout time change together, as the aggregate decided; the only write path for these columns. */
    public void applyLockout(PasswordStatus status, int failedCount, Instant lockoutTime) {
        this.passwordStatus = status;
        this.passwordFailedCount = failedCount;
        this.passwordLockoutTime = lockoutTime;
    }
}
