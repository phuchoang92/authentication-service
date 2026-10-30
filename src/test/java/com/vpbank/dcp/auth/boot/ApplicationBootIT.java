package com.vpbank.dcp.auth.boot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.gateway.SmsSenderPort;
import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * The whole application boots against real MySQL and Valkey with registration and login on. One
 * customer is registered, fails twice (CAPTCHA now required), solves a CAPTCHA, logs in (token
 * envelope decrypted with the test's Kenc), extends the session the BFF way, logs out, then fails
 * until locked and is unlocked by the bank; finally a second device gets a restricted session that
 * can neither list devices nor extend, while the first device sees itself as the trusted primary.
 * Partner ports (Customer, Keycloak admin + Direct Grant, Notification) are mocked; the CAPTCHA
 * generator is replaced by a fixed answer.
 */
@Testcontainers
@SpringBootTest(properties = {
        "auth.registration.enabled=true",
        "auth.registration.customer.origin=https://customer.test",
        "auth.registration.keycloak.base-url=https://kc.test",
        "auth.registration.keycloak.realm=test",
        "auth.registration.keycloak.admin-client-id=auth-admin",
        "auth.registration.keycloak.admin-client-secret=secret",
        "auth.registration.notification.origin=https://notify.test",
        "auth.registration.notification.service-token=token",
        "auth.login.enabled=true",
        "auth.login.keycloak.base-url=https://kc.test",
        "auth.login.keycloak.realm=test",
        "auth.login.keycloak.client-id=authentication-service",
        "auth.login.keycloak.client-secret=secret",
        "auth.mfa.origin=https://mfa.test",
        "auth.mfa.receipt-issuer=mfa-service",
        "auth.mfa.receipt-public-jwk={\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
                + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"kid\":\"mfa-receipt-1\"}"})
@AutoConfigureMockMvc
class ApplicationBootIT {
    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4");
    @Container
    static final GenericContainer<?> VALKEY = new GenericContainer<>("valkey/valkey:9.1").withExposedPorts(6379);
    private static final String ISSUER = "https://kc.test/realms/test";
    private static final String REGISTER = """
            {"customerId":"90359","userName":"alice","firstName":"Alice","lastName":"Nguyen",
             "phoneNumber":"+84901234567"}""";

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("spring.data.redis.url", () -> "redis://" + VALKEY.getHost() + ":" + VALKEY.getMappedPort(6379));
        registry.add("auth.registration.request-digest-key-base64", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("auth.captcha.answer-hmac-key-base64", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("auth.device.lookup-hmac-keys-base64.d1", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("auth.device.encryption-keys-base64.e1", () -> Base64.getEncoder().encodeToString(new byte[32]));
    }

    @Autowired MockMvc mvc;
    @Autowired CustomerAuthenticationJpaRepository identities;
    @MockitoBean CustomerDirectoryPort customers;
    @MockitoBean IdentityProviderPort keycloakAdmin;
    @MockitoBean SmsSenderPort sms;
    @MockitoBean CredentialVerifierPort credentials;
    @MockitoBean CaptchaGenerator captchaGenerator;
    @MockitoBean MfaTransactionPort mfa;

    @Test
    void registersFailsSolvesACaptchaLogsInExtendsLogsOutGetsLockedAndIsUnlocked() throws Exception {
        when(captchaGenerator.next()).thenReturn(new CaptchaGenerator.GeneratedCaptcha(new CaptchaAnswer("AB3CD"), new byte[]{1}));
        when(customers.profile(new CustomerId("90359"))).thenReturn(Optional.of(CustomerProfile.builder()
                .customerId(new CustomerId("90359")).eligible(true).phone("+84901234567").phoneVerified(true).build()));
        when(keycloakAdmin.createDisabledUser(any())).thenReturn(new CreateUserResult.Created(ISSUER, "sub-1"));
        when(sms.sendInitialPassword(any())).thenReturn(true);
        mvc.perform(post("/internal/v1/callback/authentication-creation").contentType(MediaType.APPLICATION_JSON)
                .content(REGISTER)).andExpect(status().isCreated());
        assertThat(identities.findById("90359").orElseThrow().getIdentitySubject()).isEqualTo("sub-1");

        // Two wrong passwords (same answer as an unknown user); the third attempt needs a CAPTCHA.
        ECKey kenc = new ECKeyGenerator(Curve.P_256).generate();
        String loginBody = "{\"userName\":\"alice\",\"password\":\"Secret123\",\"channel\":\"MOBILE\","
                + "\"deviceId\":\"dev-1\",\"platform\":\"ANDROID\",\"tokenEncryptionKey\":" + kenc.toPublicJWK().toJSONString() + "}";
        when(credentials.verify(eq(new UserName("alice")), any())).thenReturn(new VerificationResult.Rejected());
        for (int i = 0; i < 2; i++) {
            mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(loginBody))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"));
        }
        when(credentials.verify(eq(new UserName("alice")), any())).thenReturn(new VerificationResult.Verified(ISSUER, "sub-1"));
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(loginBody))
                .andExpect(status().isPreconditionRequired()).andExpect(jsonPath("$.error.code").value("CAPTCHA_REQUIRED"));
        MvcResult captcha = mvc.perform(post("/api/ns/v1/login/captcha").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userName\":\"alice\"}"))
                .andExpect(status().isOk()).andReturn();
        String captchaId = field(captcha.getResponse().getContentAsString(), "captchaId");
        String solved = loginBody.replace("\"deviceId\":\"dev-1\",",
                "\"deviceId\":\"dev-1\",\"captcha\":{\"captchaId\":\"" + captchaId + "\",\"answer\":\"ab3cd\"},");
        MvcResult login = mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(solved))
                .andExpect(status().isCreated())
                .andExpect(header().exists("X-Correlation-Id"))
                .andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$..token").doesNotExist())
                .andReturn();

        // Only the holder of Kenc learns the token.
        String envelope = field(login.getResponse().getContentAsString(), "tokenEnvelope");
        JWEObject jwe = JWEObject.parse(envelope);
        jwe.decrypt(new ECDHDecrypter(kenc));
        String token = field(jwe.getPayload().toString(), "token");
        assertThat(token).matches("s1:auth:session:MOBILE:[0-9a-f-]{36}:[A-Za-z0-9_-]{43}");

        // The BFF extends by the channel and session ID it reads from the token; it never sends the secret.
        String extendBody = extendBodyFor(token);
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(extendBody))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.idleExpiresAt").exists());

        // Logout needs the session; afterwards the token is dead and extend says gone.
        mvc.perform(post("/api/v1/logout")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + token)).andExpect(status().isNoContent());
        // Logout is idempotent (slice 8): a token without a live session is already logged out.
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + token)).andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + token)).andExpect(status().isUnauthorized());
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(extendBody))
                .andExpect(status().isGone());

        // The success reset the counter: two failures, then CAPTCHA + a third failure locks for 15 minutes.
        when(credentials.verify(eq(new UserName("alice")), any())).thenReturn(new VerificationResult.Rejected());
        for (int i = 0; i < 2; i++) {
            mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(loginBody))
                    .andExpect(status().isUnauthorized());
        }
        MvcResult again = mvc.perform(post("/api/ns/v1/login/captcha").contentType(MediaType.APPLICATION_JSON)
                .content("{\"userName\":\"alice\"}")).andReturn();
        String third = loginBody.replace("\"deviceId\":\"dev-1\",", "\"deviceId\":\"dev-1\",\"captcha\":{\"captchaId\":\""
                + field(again.getResponse().getContentAsString(), "captchaId") + "\",\"answer\":\"AB3CD\"},");
        mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(third))
                .andExpect(status().isLocked()).andExpect(jsonPath("$.error.code").value("ACCOUNT_LOCKED"));
        assertThat(identities.findById("90359").orElseThrow().getPasswordFailedCount()).isEqualTo(3);
        assertThat(identities.findById("90359").orElseThrow().getPasswordLockoutTime()).isNotNull();

        // The bank unlocks; the next correct login works without a CAPTCHA and is ACTIVE on the trusted primary.
        mvc.perform(post("/internal/v1/customers/90359/password-unlock")).andExpect(status().isNoContent());
        when(credentials.verify(eq(new UserName("alice")), any())).thenReturn(new VerificationResult.Verified(ISSUER, "sub-1"));
        MvcResult phoneLogin = mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(loginBody))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("ACTIVE")).andReturn();
        String phoneToken = tokenOf(phoneLogin, kenc);

        // A second installation: right password, but NEED_TRUSTED_DEVICE with a 10-minute restricted session.
        String tabletBody = loginBody.replace("\"deviceId\":\"dev-1\",\"platform\":\"ANDROID\"",
                "\"deviceId\":\"tablet-2\",\"platform\":\"IOS\"");
        MvcResult tabletLogin = mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(tabletBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("NEED_TRUSTED_DEVICE")).andReturn();
        String tabletToken = tokenOf(tabletLogin, kenc);
        mvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + tabletToken))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.code").value("DEVICE_TRUST_REQUIRED"));
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON)
                        .content(extendBodyFor(tabletToken)))
                .andExpect(status().isGone());
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + tabletToken)).andExpect(status().isNoContent());

        // The phone sees one device: itself, trusted and primary; the tablet was never registered.
        mvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + phoneToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].deviceId").value("…ev-1"))
                .andExpect(jsonPath("$.data[0].primary").value(true))
                .andExpect(jsonPath("$.data[0].trustLevel").value("TRUSTED"));

        // The tablet logs in again and enrolls: init (challenge to its key) → verify (FACE at MFA) → confirm.
        MvcResult tabletAgain = mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(tabletBody))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("NEED_TRUSTED_DEVICE")).andReturn();
        String restrictedToken = tokenOf(tabletAgain, kenc);
        ECKey deviceKey = new ECKeyGenerator(Curve.P_256).generate();
        MvcResult init = mvc.perform(post("/api/v1/trusted-device/init").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"devicePublicJwk\":" + deviceKey.toPublicJWK().toJSONString() + ",\"platform\":\"IOS\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("KEY_EXCHANGE"))
                .andExpect(jsonPath("$.data.serverPublicJwk.crv").value("P-256"))
                .andExpect(jsonPath("$..serverPrivateJwk").doesNotExist())
                .andReturn();
        String initJson = init.getResponse().getContentAsString();
        String challengeResponse = answerChallenge(initJson, deviceKey);

        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-txn-1", java.time.Instant.now().plusSeconds(300)));
        mvc.perform(post("/api/v1/trusted-device/verify").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"challengeResponse\":\"" + challengeResponse + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.data.mfaTransactionId").value("mfa-txn-1"));

        when(mfa.check(any())).thenReturn(new CheckResult.Pending());
        ECKey tabletKenc = new ECKeyGenerator(Curve.P_256).generate();
        String confirmBody = "{\"tokenEncryptionKey\":" + tabletKenc.toPublicJWK().toJSONString() + "}";
        mvc.perform(post("/api/v1/trusted-device/confirm").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(confirmBody))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("MFA_NOT_PASSED"));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("receipt-digest"));
        MvcResult confirm = mvc.perform(post("/api/v1/trusted-device/confirm").header("Authorization", "Bearer " + restrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(confirmBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$..token").doesNotExist())
                .andReturn();

        // The restricted session is gone; the new ACTIVE token is sealed to the key sent at confirm and sees two devices.
        mvc.perform(get("/api/v1/trusted-device/status").header("Authorization", "Bearer " + restrictedToken))
                .andExpect(status().isUnauthorized());
        String tabletActiveToken = tokenOf(confirm, tabletKenc);
        mvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + tabletActiveToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(2))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…ev-1')].primary").value(false))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…et-2')].primary").value(true))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…et-2')].trustLevel").value("TRUSTED"));

        // Slice 6: a watch asks to be approved; the tablet (current primary) approves with FACE + OTP and shows a QR.
        String watchBody = loginBody.replace("\"deviceId\":\"dev-1\",\"platform\":\"ANDROID\"",
                "\"deviceId\":\"watch-3\",\"platform\":\"IOS\"");
        MvcResult watchLogin = mvc.perform(post("/api/ns/v1/login").contentType(MediaType.APPLICATION_JSON).content(watchBody))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("NEED_TRUSTED_DEVICE")).andReturn();
        String watchRestrictedToken = tokenOf(watchLogin, kenc);
        ECKey watchKey = new ECKeyGenerator(Curve.P_256).generate();
        MvcResult request = mvc.perform(post("/api/v1/trusted-device/request").header("Authorization", "Bearer " + watchRestrictedToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"devicePublicJwk\":" + watchKey.toPublicJWK().toJSONString() + ",\"platform\":\"IOS\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("WAITING_APPROVAL")).andReturn();
        String approvalId = field(request.getResponse().getContentAsString(), "enrollmentId");
        mvc.perform(get("/api/v1/trusted-device/status").header("Authorization", "Bearer " + watchRestrictedToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("WAITING_APPROVAL"));

        mvc.perform(get("/api/v1/trusted-device/pending").header("Authorization", "Bearer " + phoneToken))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.code").value("NOT_PRIMARY_DEVICE"));
        mvc.perform(get("/api/v1/trusted-device/pending").header("Authorization", "Bearer " + tabletActiveToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].enrollmentId").value(approvalId))
                .andExpect(jsonPath("$.data[0].deviceId").value("…ch-3"))
                .andExpect(jsonPath("$.data[0].platform").value("IOS"));
        when(mfa.create(any())).thenReturn(new CreateResult.Created("mfa-txn-2", java.time.Instant.now().plusSeconds(300)));
        mvc.perform(post("/api/v1/trusted-device/pending/" + approvalId + "/approve").header("Authorization", "Bearer " + tabletActiveToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.data.mfaTransactionId").value("mfa-txn-2"));
        when(mfa.check(any())).thenReturn(new CheckResult.Passed("approval-receipt"));
        MvcResult authorize = mvc.perform(post("/api/v1/trusted-device/pending/" + approvalId + "/authorize")
                        .header("Authorization", "Bearer " + tabletActiveToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("WAITING_AUTHORIZATION")).andReturn();
        String qrToken = field(authorize.getResponse().getContentAsString(), "authorizationToken");
        mvc.perform(get("/api/v1/trusted-device/status").header("Authorization", "Bearer " + watchRestrictedToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("WAITING_AUTHORIZATION"));

        // The watch scans the QR: a wrong token costs an attempt, the right one makes it trusted and primary.
        ECKey watchKenc = new ECKeyGenerator(Curve.P_256).generate();
        String claimBody = "{\"authorizationToken\":\"" + qrToken + "\",\"tokenEncryptionKey\":" + watchKenc.toPublicJWK().toJSONString() + "}";
        mvc.perform(post("/api/v1/trusted-device/claim").header("Authorization", "Bearer " + watchRestrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(claimBody.replace(qrToken, "not-the-qr-token")))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error.code").value("WRONG_AUTHORIZATION"))
                .andExpect(jsonPath("$.error.details[0].message").value("4"));
        MvcResult claim = mvc.perform(post("/api/v1/trusted-device/claim").header("Authorization", "Bearer " + watchRestrictedToken)
                        .contentType(MediaType.APPLICATION_JSON).content(claimBody))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$..token").doesNotExist()).andReturn();
        mvc.perform(get("/api/v1/trusted-device/status").header("Authorization", "Bearer " + watchRestrictedToken))
                .andExpect(status().isUnauthorized());
        String watchActiveToken = tokenOf(claim, watchKenc);
        mvc.perform(get("/api/v1/devices").header("Authorization", "Bearer " + watchActiveToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(3))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…ch-3')].primary").value(true))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…ch-3')].trustLevel").value("TRUSTED"))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…et-2')].primary").value(false))
                .andExpect(jsonPath("$.data[?(@.deviceId == '…et-2')].trustLevel").value("TRUSTED"));
        mvc.perform(get("/api/v1/trusted-device/pending").header("Authorization", "Bearer " + watchActiveToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.length()").value(0));
    }

    /** Plays the app: open the challenge with the device key and re-seal it to Ksrv (DD 20 §6a). */
    private static String answerChallenge(String initJson, ECKey deviceKey) throws Exception {
        JWEObject challengeJwe = JWEObject.parse(field(initJson, "challenge"));
        challengeJwe.decrypt(new ECDHDecrypter(deviceKey));
        Map<String, Object> challengePayload = challengeJwe.getPayload().toJSONObject();

        Matcher serverJwk = Pattern.compile("\"serverPublicJwk\":(\\{[^}]+\\})").matcher(initJson);
        assertThat(serverJwk.find()).isTrue();
        ECKey ksrv = ECKey.parse(serverJwk.group(1));

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .type(new JOSEObjectType("trusted-device-challenge-response+jwe"))
                .build();
        JWEObject response = new JWEObject(header, new Payload(challengePayload));
        response.encrypt(new ECDHEncrypter(ksrv));
        return response.serialize();
    }

    private static String tokenOf(MvcResult login, ECKey kenc) throws Exception {
        JWEObject jwe = JWEObject.parse(field(login.getResponse().getContentAsString(), "tokenEnvelope"));
        jwe.decrypt(new ECDHDecrypter(kenc));
        return field(jwe.getPayload().toString(), "token");
    }

    private static String extendBodyFor(String token) {
        String[] parts = token.split(":");
        String channel = parts[3];
        String sessionId = parts[4];
        return "{\"sessionLookup\":{\"channel\":\"" + channel + "\",\"sessionId\":\"" + sessionId + "\"},"
                + "\"admittedAt\":\"" + java.time.Instant.now() + "\",\"routeId\":\"accounts.read\"}";
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]+)\"").matcher(json);
        assertThat(m.find()).as(name + " in " + json).isTrue();
        return m.group(1);
    }
}
