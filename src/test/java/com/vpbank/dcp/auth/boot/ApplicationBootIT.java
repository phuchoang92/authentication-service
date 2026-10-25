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

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.CustomerDirectoryPort;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort.CreateUserResult;
import com.vpbank.dcp.auth.application.port.out.gateway.IdentityProviderPort;
import com.vpbank.dcp.auth.application.port.out.gateway.SmsSenderPort;
import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.CustomerAuthenticationJpaRepository;
import java.util.Base64;
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
        registry.add("auth.session.lookup-hmac-keys-base64.k1", () -> Base64.getEncoder().encodeToString(new byte[32]));
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
        assertThat(token).matches("k1\\.[A-Za-z0-9_-]{43}");

        // The BFF extends by lookup digest = HMAC(zero key, token).
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(new byte[32], "HmacSHA256"));
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(token.getBytes()));
        String extendBody = "{\"sessionLookup\":{\"lookupKeyVersion\":\"k1\",\"lookupDigest\":\"" + digest + "\"},"
                + "\"admittedAt\":\"" + java.time.Instant.now() + "\",\"routeId\":\"accounts.read\"}";
        mvc.perform(post("/internal/v1/sessions/extend").contentType(MediaType.APPLICATION_JSON).content(extendBody))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.idleExpiresAt").exists());

        // Logout needs the session; afterwards the token is dead and extend says gone.
        mvc.perform(post("/api/v1/logout")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + token)).andExpect(status().isNoContent());
        mvc.perform(post("/api/v1/logout").header("Authorization", "Bearer " + token)).andExpect(status().isUnauthorized());
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
    }

    private static String tokenOf(MvcResult login, ECKey kenc) throws Exception {
        JWEObject jwe = JWEObject.parse(field(login.getResponse().getContentAsString(), "tokenEnvelope"));
        jwe.decrypt(new ECDHDecrypter(kenc));
        return field(jwe.getPayload().toString(), "token");
    }

    private static String extendBodyFor(String token) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(new byte[32], "HmacSHA256"));
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(token.getBytes()));
        return "{\"sessionLookup\":{\"lookupKeyVersion\":\"k1\",\"lookupDigest\":\"" + digest + "\"},"
                + "\"admittedAt\":\"" + java.time.Instant.now() + "\",\"routeId\":\"accounts.read\"}";
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]+)\"").matcher(json);
        assertThat(m.find()).as(name + " in " + json).isTrue();
        return m.group(1);
    }
}
