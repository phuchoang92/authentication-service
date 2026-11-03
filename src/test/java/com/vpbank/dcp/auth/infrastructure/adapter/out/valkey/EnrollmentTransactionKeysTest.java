package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import org.junit.jupiter.api.Test;

class EnrollmentTransactionKeysTest {
    private final EnrollmentTransactionKeys keys = new EnrollmentTransactionKeys();

    @Test
    void theKeyIsChannelCustomerAndDeviceInClear() {
        assertThat(keys.forDevice(new CustomerId("90359"), Channel.MOBILE, new DeviceId("tablet-2")))
                .isEqualTo("enrollment-tx:v1:MOBILE:90359:tablet-2");
    }

    @Test
    void eachDimensionChangesTheKey() {
        String tablet = keys.forDevice(new CustomerId("90359"), Channel.MOBILE, new DeviceId("tablet-2"));
        assertThat(keys.forDevice(new CustomerId("90360"), Channel.MOBILE, new DeviceId("tablet-2"))).isNotEqualTo(tablet);
        assertThat(keys.forDevice(new CustomerId("90359"), Channel.WEB, new DeviceId("tablet-2"))).isNotEqualTo(tablet);
        assertThat(keys.forDevice(new CustomerId("90359"), Channel.MOBILE, new DeviceId("tablet-3"))).isNotEqualTo(tablet);
    }
}
