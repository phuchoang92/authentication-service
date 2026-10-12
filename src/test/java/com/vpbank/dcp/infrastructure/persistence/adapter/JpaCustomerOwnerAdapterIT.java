package com.vpbank.dcp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.application.password.ResolveTrustedDeviceRouteService;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerAcceptance;
import com.vpbank.dcp.core.port.out.customer.CustomerOwnerRepository;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import com.vpbank.dcp.core.port.out.password.PasswordDispatchResult;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteRepository;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordReservation;
import com.vpbank.dcp.core.port.out.password.PasswordReservationFingerprints;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "server.ssl.enabled=false",
        "auth.authority.scope=bank-test-neo",
        "auth.ingress.external-origin=https://api.bank.test",
        "auth.ingress.allowed-workload-uris=spiffe://bank.test/mobile-bff",
        "spring.datasource.hikari.maximum-pool-size=10",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=1",
        "spring.data.redis.ssl.enabled=false"
})
class JpaCustomerOwnerAdapterIT {

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>(
            DockerImageName.parse("mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"))
            .withDatabaseName("auth_customer_owner")
            .withUsername("auth_test")
            .withPassword("test-only-password");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
    }

    @Autowired
    private CustomerOwnerRepository owners;

    @Autowired
    private PasswordOperationRepository operations;

    @Autowired
    private PasswordDeviceRouteRepository deviceRoutes;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void clearState() {
        jdbc.update("DELETE FROM auth_security_guard");
        jdbc.update("DELETE FROM auth_operation WHERE kind = 'PASSWORD_LOGIN'");
        jdbc.update("DELETE FROM auth_login_journey WHERE method = 'PASSWORD'");
        jdbc.update("UPDATE auth_subject_app SET last_successful_binding_id = NULL");
        jdbc.update("DELETE FROM auth_device_key");
        jdbc.update("DELETE FROM auth_device_binding");
        jdbc.update("DELETE FROM auth_identity_link");
        jdbc.update("DELETE FROM auth_subject_app");
        jdbc.update("DELETE FROM auth_customer");
    }

    @Test
    void verifiedIdentityAndCustomerBecomeOneDurableOwner() {
        UUID operationId = verifiedOperation(1, "kc-a");
        CustomerOwnerAcceptance result = owners.accept(operationId, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy");

        assertThat(result).isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        UUID subjectId = ((CustomerOwnerAcceptance.Accepted) result).subjectId();
        assertThat(jdbc.queryForObject("""
                SELECT BIN_TO_UUID(subject_id) FROM auth_operation WHERE id = UUID_TO_BIN(?)
                """, String.class, operationId.toString())).isEqualTo(subjectId.toString());
        assertThat(jdbc.queryForObject("""
                SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)
                """, String.class, operationId.toString())).isEqualTo("CONFIRMED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_identity_link", Integer.class))
                .isEqualTo(1);
        assertThat(operations.confirmedOwner(operationId)).isPresent().get()
                .satisfies(owner -> {
                    assertThat(owner.subjectId()).isEqualTo(subjectId);
                    assertThat(owner.identity()).isEqualTo(identity("kc-a"));
                    assertThat(owner.customer().customerId()).isEqualTo("CUST-1");
                });
        assertThat(owners.accept(operationId, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.NotClaimable.class);
    }

    @Test
    void newDeviceWithoutMfaFreezesUnavailableResultWithoutIssuingToken() {
        UUID operationId = verifiedOperation(101, "kc-a");
        assertThat(owners.accept(operationId, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Accepted.class);

        assertThat(operations.recordMfaUnavailable(operationId, TrustedDeviceRoute.NEW_DEVICE))
                .isEqualTo(PasswordCredentialRecordResult.RECORDED);
        assertThat(operations.recordMfaUnavailable(operationId, TrustedDeviceRoute.NEW_DEVICE))
                .isEqualTo(PasswordCredentialRecordResult.ALREADY_RECORDED);
        assertThat(operations.progress(operationId)).isEqualTo(PasswordOperationProgress.MFA_UNAVAILABLE);
        assertThat(operations.claimDispatch(operationId)).isEqualTo(PasswordDispatchResult.ALREADY_CLAIMED);
        assertThat(jdbc.queryForObject("""
                SELECT CONCAT(state, ':', route) FROM auth_login_journey
                 WHERE id = (SELECT journey_id FROM auth_operation WHERE id = UUID_TO_BIN(?))
                """, String.class, operationId.toString())).isEqualTo("FAILED:NEW_DEVICE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_authority_intent", Integer.class))
                .isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_result_escrow", Integer.class))
                .isZero();
    }

    @Test
    void differentProviderSubjectCannotTakeExistingCustomer() {
        UUID first = verifiedOperation(2, "kc-a");
        assertThat(owners.accept(first, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        UUID second = verifiedOperation(3, "kc-b");

        assertThat(owners.accept(second, "neo-mobile", identity("kc-b"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Conflict.class);
        assertThat(operationState(second)).isEqualTo("VERIFIED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_identity_link", Integer.class))
                .isEqualTo(1);
    }

    @Test
    void advancedBlockWatermarkRequiresRevocationBeforeOwnerAcceptance() {
        UUID first = verifiedOperation(4, "kc-a");
        assertThat(owners.accept(first, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        UUID second = verifiedOperation(5, "kc-a");

        assertThat(owners.accept(second, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 3, 2), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.ReconciliationRequired.class);
        assertThat(operationState(second)).isEqualTo("VERIFIED");
        assertThat(jdbc.queryForObject("SELECT customer_last_block_version FROM auth_customer",
                Long.class)).isZero();
    }

    @Test
    void locallyBlockedCustomerCannotBeReopenedByLoginSnapshot() {
        UUID first = verifiedOperation(6, "kc-a");
        assertThat(owners.accept(first, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        jdbc.update("""
                UPDATE auth_customer SET status = 'BLOCKED', customer_status_version = 2,
                   customer_last_block_version = 2
                """);
        UUID second = verifiedOperation(7, "kc-a");

        assertThat(owners.accept(second, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 3, 2), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.ReconciliationRequired.class);
        assertThat(operationState(second)).isEqualTo("VERIFIED");
    }

    @Test
    void customerWideGuardDeniesOwnerAcceptance() {
        UUID first = verifiedOperation(8, "kc-a");
        CustomerOwnerAcceptance.Accepted accepted = (CustomerOwnerAcceptance.Accepted) owners.accept(
                first, "neo-mobile", identity("kc-a"), customer("CUST-1", 1, 0), "test-policy");
        UUID subjectId = accepted.subjectId();
        jdbc.update("""
                INSERT INTO auth_security_guard
                  (id, subject_id, scope, scope_id, customer_deny,
                   min_customer_security_version, min_credential_security_version,
                   generation, operation_id, effective_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'SUBJECT', UUID_TO_BIN(?), 1,
                        0, 0, UUID_TO_BIN(?), UUID_TO_BIN(?), UTC_TIMESTAMP(6),
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), subjectId.toString(), subjectId.toString(),
                UUID.randomUUID().toString(), first.toString());
        UUID second = verifiedOperation(9, "kc-a");

        assertThat(owners.accept(second, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Rejected.class);
        assertThat(operationState(second)).isEqualTo("VERIFIED");
    }

    @Test
    void oneProviderIdentityCannotBelongToTwoCustomers() {
        UUID first = verifiedOperation(10, "kc-a");
        assertThat(owners.accept(first, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        UUID second = verifiedOperation(11, "kc-a");

        assertThat(owners.accept(second, "neo-mobile", identity("kc-a"),
                customer("CUST-2", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Conflict.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM auth_customer", Integer.class))
                .isEqualTo(1);
        assertThat(operationState(second)).isEqualTo("VERIFIED");
    }

    @Test
    void currentBindingAndPinnedKdevDecideLastTrustedRoute() {
        UUID first = verifiedOperation(12, "kc-a");
        UUID subjectId = ((CustomerOwnerAcceptance.Accepted) owners.accept(first,
                "neo-mobile", identity("kc-a"), customer("CUST-1", 1, 0),
                "test-policy")).subjectId();
        UUID bindingId = UUID.randomUUID();
        byte[] installationHash = digest(8).bytes();
        jdbc.update("""
                INSERT INTO auth_device_binding
                (id, subject_id, app_id, installation_hash, platform, label,
                 status, policy_version, possession_assurance, platform_assurance,
                 trusted_at, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', ?, 'ANDROID',
                        'Test phone', 'ACTIVE', 'test-policy', 'MFA_KEY_POSSESSION',
                        'NONE', UTC_TIMESTAMP(6), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY),
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, bindingId.toString(), subjectId.toString(), installationHash);
        jdbc.update("""
                INSERT INTO auth_device_key
                (id, subject_id, app_id, binding_id, purpose, public_key_spki,
                 jkt, algorithm, status, expires_at, created_at, updated_at)
                VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?), 'neo-mobile', UUID_TO_BIN(?),
                        'DEVICE_POSSESSION', ?, ?, 'ES256', 'ACTIVE',
                        DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY),
                        UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
                """, UUID.randomUUID().toString(), subjectId.toString(), bindingId.toString(),
                new byte[64], digest(5).bytes());
        jdbc.update("""
                UPDATE auth_subject_app SET last_successful_binding_id = UUID_TO_BIN(?)
                 WHERE subject_id = UUID_TO_BIN(?) AND app_id = 'neo-mobile'
                """, bindingId.toString(), subjectId.toString());

        UUID current = verifiedOperationWithBinding(13, bindingId, digest(5));
        assertThat(owners.accept(current, "neo-mobile", identity("kc-a"),
                customer("CUST-1", 1, 0), "test-policy"))
                .isInstanceOf(CustomerOwnerAcceptance.Accepted.class);
        ResolveTrustedDeviceRouteService routing = new ResolveTrustedDeviceRouteService(
                deviceRoutes, new TrustedDeviceRouting());
        assertThat(routing.resolve(current, subjectId, "neo-mobile", Instant.now()))
                .isEqualTo(TrustedDeviceRoute.LAST_TRUSTED);
        jdbc.update("UPDATE auth_device_key SET status = 'REVOKED' WHERE binding_id = UUID_TO_BIN(?)",
                bindingId.toString());
        assertThat(routing.resolve(current, subjectId, "neo-mobile", Instant.now()))
                .isEqualTo(TrustedDeviceRoute.REJECTED);
    }

    private UUID verifiedOperation(int marker, String providerSubject) {
        return verifiedOperationWithBinding(marker, null, null, providerSubject);
    }

    private UUID verifiedOperationWithBinding(int marker, UUID bindingId,
                                               Digest32 deviceJkt) {
        return verifiedOperationWithBinding(marker, bindingId, deviceJkt, "kc-a");
    }

    private UUID verifiedOperationWithBinding(int marker, UUID bindingId,
                                               Digest32 deviceJkt, String providerSubject) {
        UUID operationId = UUID.randomUUID();
        Instant now = Instant.now();
        PasswordReservation reservation = new PasswordReservation(
                new PasswordOperationContext(operationId, "neo-mobile", "ANDROID",
                        "install-test", "alice", bindingId),
                new VerifiedPasswordProofs(new RequestKeyThumbprint(digest(1)), digest(2),
                        deviceJkt,
                        new PasswordProofIds(digest(3), digest(4),
                                deviceJkt == null ? null : digest(9)), "{}", "{}"),
                new PasswordReservationFingerprints(digest(marker + 10), digest(marker + 20),
                        digest(marker + 30), "test-key", digest(8)), now,
                now.plusSeconds(120), now.plusSeconds(300));
        operations.reserve(reservation);
        operations.claimDispatch(operationId);
        operations.recordVerifiedIdentity(operationId, identity(providerSubject));
        return operationId;
    }

    private CustomerAuthenticationState customer(String customerId, long version, long block) {
        return new CustomerAuthenticationState(customerId, CustomerStatus.ELIGIBLE,
                version, block, Instant.now());
    }

    private VerifiedProviderIdentity identity(String subject) {
        return new VerifiedProviderIdentity("https://auth.bank.test/realms/mobile", subject);
    }

    private String operationState(UUID operationId) {
        return jdbc.queryForObject("SELECT state FROM auth_operation WHERE id = UUID_TO_BIN(?)",
                String.class, operationId.toString());
    }

    private Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) marker);
        return Digest32.fromBytes(bytes);
    }
}
