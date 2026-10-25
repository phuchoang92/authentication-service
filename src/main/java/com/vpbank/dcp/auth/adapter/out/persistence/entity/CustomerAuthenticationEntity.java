package com.vpbank.dcp.auth.adapter.out.persistence.entity;

import com.vpbank.dcp.auth.adapter.out.persistence.common.AuditedEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Row of CUSTOMER_AUTHENTICATION: the identity a customer logs in with (design phase 1). */
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

    @Version
    @Column(name = "VERSION", nullable = false)
    private long version;
}
