package com.vpbank.dcp.infrastructure.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.customer.InvalidCustomerStateException;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import com.vpbank.dcp.infrastructure.persistence.projection.ConfirmedPasswordOwnerView;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordOperationProgressView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordReservationView;
import com.vpbank.dcp.infrastructure.persistence.projection.VerifiedPasswordIdentityView;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordOperationPersistenceMapperTest {
    @Test
    void preservesEveryOperationStateAndRejectsUnknownCodes() {
        for (PasswordOperationProgress state : PasswordOperationProgress.values()) {
            assertThat(PasswordOperationPersistenceMapper.toProgress(
                    new PasswordOperationProgressView(state.name()))).isEqualTo(state);
        }
        assertThatThrownBy(() -> PasswordOperationPersistenceMapper.toProgress(
                new PasswordOperationProgressView("verified"))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void restoresVerifiedIdentityWithoutNormalizingIssuerOrSubject() {
        var view = new VerifiedPasswordIdentityView("https://auth.bank.test/realms/Mobile", "Subject:AbC");
        assertThat(PasswordOperationPersistenceMapper.toVerifiedIdentity(view)).isEqualTo(
                new VerifiedProviderIdentity("https://auth.bank.test/realms/Mobile", "Subject:AbC"));
        assertThatThrownBy(() -> PasswordOperationPersistenceMapper.toVerifiedIdentity(
                new VerifiedPasswordIdentityView("http://auth.bank.test", "subject")))
                .isInstanceOf(InvalidCustomerStateException.class);
    }

    @Test
    void restoresConfirmedOwnerWithExactSubjectAndCustomerWatermarks() {
        UUID subjectId = UUID.randomUUID();
        var customer = new CustomerOwnerView(subjectId, "CUST-9", "ELIGIBLE", 25, 17, Instant.EPOCH);
        var owner = PasswordOperationPersistenceMapper.toConfirmedOwner(
                new ConfirmedPasswordOwnerView("https://auth.bank.test", "kc-9", customer));
        assertThat(owner.subjectId()).isEqualTo(subjectId);
        assertThat(owner.identity()).isEqualTo(new VerifiedProviderIdentity("https://auth.bank.test", "kc-9"));
        assertThat(owner.customer()).isEqualTo(CustomerOwnerPersistenceMapper.toDomain(customer));
    }

    @Test
    void restoresDuplicateReservationWithExactIdsAndStoredDigestSelector() {
        UUID operationId = UUID.randomUUID();
        UUID journeyId = UUID.randomUUID();
        byte[] digest = new byte[32];
        digest[7] = 42;
        var existing = PasswordOperationPersistenceMapper.toExistingReservation(
                new PasswordReservationView(operationId, journeyId, digest, "command-k2"));
        assertThat(existing.operationId()).isEqualTo(operationId);
        assertThat(existing.journeyId()).isEqualTo(journeyId);
        assertThat(existing.commandDigest().bytes()).isEqualTo(digest);
        assertThat(existing.commandKeyId()).isEqualTo("command-k2");
        assertThatThrownBy(() -> PasswordOperationPersistenceMapper.toExistingReservation(
                new PasswordReservationView(operationId, journeyId, new byte[31], "command-k2")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
