package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper;

import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.domain.enums.PasswordStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.Registration;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.RequestDigest;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.CustomerAuthenticationEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.RegistrationEntity;

/** Registration aggregate ↔ phase-1 rows. Value objects are built on the way out of the database. */
public final class RegistrationPersistenceMapper {
    private RegistrationPersistenceMapper() {
    }

    public static RegistrationEntity toEntity(Registration registration) {
        return RegistrationEntity.builder()
                .requestId(registration.id().value())
                .customerId(registration.customerId().value())
                .userName(registration.userName().value())
                .requestDigest(registration.requestDigest().bytes())
                .state(registration.state())
                .identityIssuer(registration.identityIssuer())
                .identitySubject(registration.identitySubject())
                .expiresAt(registration.expiresAt())
                .version(registration.version())
                .build();
    }

    public static Registration toDomain(RegistrationEntity entity) {
        return Registration.builder()
                .id(new RegistrationId(entity.getRequestId()))
                .customerId(new CustomerId(entity.getCustomerId()))
                .userName(new UserName(entity.getUserName()))
                .requestDigest(new RequestDigest(entity.getRequestDigest()))
                .state(entity.getState())
                .identityIssuer(entity.getIdentityIssuer())
                .identitySubject(entity.getIdentitySubject())
                .expiresAt(entity.getExpiresAt())
                .version(entity.getVersion())
                .build();
    }

    /** Copies the step the aggregate decided onto the managed row. */
    public static void apply(RegistrationEntity entity, Registration changed) {
        entity.applyStep(changed.state(), changed.identityIssuer(), changed.identitySubject());
    }

    /** The identity row written when a registration completes. */
    public static CustomerAuthenticationEntity toIdentity(Registration completed) {
        return CustomerAuthenticationEntity.builder()
                .customerId(completed.customerId().value())
                .userName(completed.userName().value())
                .identityIssuer(completed.identityIssuer())
                .identitySubject(completed.identitySubject())
                .status(CustomerAuthenticationEntity.STATUS_ACTIVE)
                .passwordStatus(PasswordStatus.ACTIVE)
                .passwordFailedCount(0)
                .build();
    }

    /** The identity row as the login flow reads it. */
    public static CustomerAuthentication toIdentity(CustomerAuthenticationEntity entity) {
        return CustomerAuthentication.builder()
                .customerId(new CustomerId(entity.getCustomerId()))
                .userName(new UserName(entity.getUserName()))
                .identityIssuer(entity.getIdentityIssuer())
                .identitySubject(entity.getIdentitySubject())
                .status(entity.getStatus())
                .lockout(new PasswordLockout(entity.getPasswordStatus(), entity.getPasswordFailedCount(),
                        entity.getPasswordLockoutTime()))
                .version(entity.getVersion())
                .build();
    }

    /** Copies the lockout the aggregate decided onto the managed row. */
    public static void applyLockout(CustomerAuthenticationEntity entity, PasswordLockout lockout) {
        entity.applyLockout(lockout.status(), lockout.failedCount(), lockout.lockedUntil());
    }
}
