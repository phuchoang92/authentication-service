package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.domain.customer.CustomerOwnerPolicy;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.device.LoginDeviceRepository;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityStore;
import com.vpbank.dcp.infrastructure.config.properties.DeviceIdProtectionProperties;
import com.vpbank.dcp.infrastructure.id.OpaqueBindingIdCodec;
import com.vpbank.dcp.infrastructure.persistence.adapter.JpaCustomerOwnerAdapter;
import com.vpbank.dcp.infrastructure.persistence.adapter.JpaLoginDeviceAdapter;
import com.vpbank.dcp.infrastructure.persistence.adapter.JpaLoginSessionSecurityStore;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdCodec;
import com.vpbank.dcp.infrastructure.persistence.codec.DeviceIdKeyMaterial;
import com.vpbank.dcp.infrastructure.persistence.repository.CustomerOwnerPersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.LoginDevicePersistenceRepository;
import com.vpbank.dcp.infrastructure.persistence.repository.LoginSessionSecurityPersistenceRepository;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.transaction.support.TransactionTemplate;

/** New-schema database adapters are assembled only in the isolated integration profile. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@EnableConfigurationProperties(DeviceIdProtectionProperties.class)
public class DeviceLoginPersistenceConfiguration {

    @Bean
    DeviceIdCodec deviceIdCodec(DeviceIdProtectionProperties properties, SecureRandom random) {
        try {
            DeviceIdKeyMaterial lookup = new DeviceIdKeyMaterial(properties.lookupKeyId(),
                    Map.of(properties.lookupKeyId(), Base64.getDecoder().decode(properties.lookupKeyBase64())));
            DeviceIdKeyMaterial encryption = new DeviceIdKeyMaterial(properties.encryptionKeyId(),
                    Map.of(properties.encryptionKeyId(),
                            Base64.getDecoder().decode(properties.encryptionKeyBase64())));
            return new DeviceIdCodec(lookup, encryption, random);
        } catch (IllegalArgumentException failure) {
            throw new InvalidLoginIntegrationConfigurationException(failure);
        }
    }

    @Bean
    OpaqueBindingIdCodec opaqueBindingIdCodec() {
        return new OpaqueBindingIdCodec();
    }

    @Bean
    LoginDeviceRepository loginDeviceRepository(LoginDevicePersistenceRepository repository,
                                                DeviceIdCodec deviceIds,
                                                OpaqueBindingIdCodec publicIds,
                                                TransactionTemplate transactions) {
        return new JpaLoginDeviceAdapter(repository, deviceIds, publicIds, transactions);
    }

    @Bean
    CustomerOwnerRepository customerOwnerRepository(CustomerOwnerPersistenceRepository repository,
                                                    TransactionTemplate transactions) {
        return new JpaCustomerOwnerAdapter(repository, new CustomerOwnerPolicy(), transactions);
    }

    @Bean
    LoginSessionSecurityStore loginSessionSecurityStore(LoginSessionSecurityPersistenceRepository repository,
                                                        TransactionTemplate transactions) {
        return new JpaLoginSessionSecurityStore(repository, transactions);
    }

}
