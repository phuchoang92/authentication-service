package com.vpbank.dcp.infrastructure.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.port.out.password.InvalidPasswordOperationException;
import com.vpbank.dcp.infrastructure.persistence.projection.StoredDeviceKeyView;
import org.junit.jupiter.api.Test;

class PasswordDeviceKeyPersistenceMapperTest {
    @Test
    void restoresExactKeyAndThumbprintWithIndependentByteOwnership() {
        byte[] spki = {1, 2, 3};
        byte[] digest = new byte[32];
        digest[0] = 17;
        var view = new StoredDeviceKeyView(spki, digest);
        var key = PasswordDeviceKeyPersistenceMapper.toDomain(view);
        spki[0] = 9;
        digest[0] = 9;
        view.publicKeySpki()[0] = 8;
        key.publicKeySpki()[0] = 7;
        assertThat(key.publicKeySpki()).containsExactly(1, 2, 3);
        assertThat(key.thumbprint().bytes()[0]).isEqualTo((byte) 17);
    }

    @Test
    void malformedStoredKeyOrDigestStillFailsRestoration() {
        assertThatThrownBy(() -> PasswordDeviceKeyPersistenceMapper.toDomain(
                new StoredDeviceKeyView(new byte[0], new byte[32])))
                .isInstanceOf(InvalidPasswordOperationException.class);
        assertThatThrownBy(() -> PasswordDeviceKeyPersistenceMapper.toDomain(
                new StoredDeviceKeyView(new byte[]{1}, new byte[31])))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
