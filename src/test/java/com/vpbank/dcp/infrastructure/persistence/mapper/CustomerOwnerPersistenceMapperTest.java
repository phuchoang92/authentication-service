package com.vpbank.dcp.infrastructure.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.InvalidCustomerStateException;
import com.vpbank.dcp.infrastructure.persistence.projection.CustomerOwnerView;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CustomerOwnerPersistenceMapperTest {
    @Test
    void restoresVersionsAndUtcCheckedAtWithoutCalculatingFreshness() {
        Instant checkedAt = LocalDateTime.parse("2026-10-12T14:00:00.123456").toInstant(ZoneOffset.UTC);
        var view = new CustomerOwnerView(UUID.randomUUID(), "CUST-1", "ELIGIBLE", 37, 9, checkedAt);
        assertThat(CustomerOwnerPersistenceMapper.toDomain(view)).isEqualTo(
                new CustomerAuthenticationState("CUST-1", CustomerStatus.ELIGIBLE, 37, 9, checkedAt));
    }

    @Test
    void preservesBlockedStatusWithoutConvertingItToEligible() {
        var view = new CustomerOwnerView(UUID.randomUUID(), "CUST-2", "BLOCKED", 8, 8, Instant.EPOCH);
        assertThat(CustomerOwnerPersistenceMapper.toDomain(view).status()).isEqualTo(CustomerStatus.BLOCKED);
    }

    @Test
    void unknownStatusAndInvalidWatermarkRemainErrors() {
        var unknown = new CustomerOwnerView(UUID.randomUUID(), "CUST-3", "UNKNOWN", 4, 0, Instant.EPOCH);
        assertThatThrownBy(() -> CustomerOwnerPersistenceMapper.toDomain(unknown))
                .isInstanceOf(IllegalArgumentException.class);
        var invalid = new CustomerOwnerView(UUID.randomUUID(), "CUST-3", "ELIGIBLE", 4, 5, Instant.EPOCH);
        assertThatThrownBy(() -> CustomerOwnerPersistenceMapper.toDomain(invalid))
                .isInstanceOf(InvalidCustomerStateException.class);
    }
}
