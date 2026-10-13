package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.infrastructure.adapter.in.web.security.constant.DpopRequestAttributes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.DpopProofFilter;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.config.properties.IngressProperties;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.test.context.support.TestPropertySourceUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import tools.jackson.databind.json.JsonMapper;

class SecurityConfigurationTest {
    private static final String PATH = "/internal/v1/authentications/password";
    private static final String URI = "https://api.bank.example/api/v1/authentications/password";
    private static final String WORKLOAD = "spiffe://bank.test/mobile-bff";
    private static final Instant NOW = Instant.parse("2026-10-12T00:00:00Z");
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;
    private Probe probe;
    private ECKey key;

    @BeforeEach
    void setUp() throws Exception {
        startContext(false);
        key = new ECKeyGenerator(Curve.P_256).generate();
    }

    private void startContext(boolean disableDpop) {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        if (disableDpop) {
            context.getEnvironment().setActiveProfiles("dev");
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(context, "auth.dpop.enabled=false");
        }
        context.register(TestConfiguration.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        probe = context.getBean(Probe.class);
    }

    @AfterEach
    void closeContext() {
        context.close();
    }

    @Test
    void x509AndDpopRunInTheActualStatelessSpringSecurityChain() throws Exception {
        var response = mvc.perform(request().header("DPoP", proof(URI))
                        .header("X-Forwarded-Host", "attacker.example")
                        .header("X-Verified-Request-Key", "attacker-key"))
                .andExpect(status().isOk()).andReturn();
        assertThat(probe.calls.get()).isEqualTo(1);
        assertThat(probe.verified.publicJwk()).isEqualTo(key.toPublicJWK().toJSONString());
        assertThat(probe.verified.requestKey().digest().base64Url()).isEqualTo(key.computeThumbprint().toString());
        assertThat(probe.workload).isEqualTo(WORKLOAD);
        assertThat(response.getRequest().getSession(false)).isNull();
        assertThat(response.getResponse().getHeader("Set-Cookie")).isNull();
    }

    @Test
    void workloadRejectionPrecedesDpopAndJsonParsing() throws Exception {
        var requests = List.of(
                post(PATH).secure(true),
                request().secure(false),
                request().requestAttr("jakarta.servlet.request.X509Certificate", certificates(2, WORKLOAD)),
                request().requestAttr("jakarta.servlet.request.X509Certificate", certificates(6, WORKLOAD + "-attacker")));
        for (var request : requests) {
            var response = mvc.perform(request.contentType(MediaType.APPLICATION_JSON).content("invalid-json"))
                    .andExpect(status().isForbidden()).andReturn().getResponse();
            assertThat(response.getContentAsString()).doesNotContain("spiffe", "certificate");
            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        }
        var expired = certificates(6, WORKLOAD);
        doThrow(new CertificateExpiredException()).when(expired[0]).checkValidity();
        mvc.perform(request().requestAttr("jakarta.servlet.request.X509Certificate", expired))
                .andExpect(status().isForbidden());
        assertThat(probe.calls.get()).isZero();
    }

    @Test
    void invalidDpopIsRejectedBeforeBodyParsingAndCannotBeSuppliedAsARequestAttribute() throws Exception {
        for (String dpop : List.of("p".repeat(64), proof("https://attacker.example/api/v1/authentications/password"))) {
            var response = mvc.perform(request().header("DPoP", dpop).content("invalid-json")
                            .requestAttr(DpopRequestAttributes.VERIFIED_DPOP_PROOF, mock(VerifiedDpopProof.class)))
                    .andExpect(status().isUnauthorized()).andReturn().getResponse();
            assertThat(response.getContentAsString()).contains("REQUEST_REJECTED").doesNotContain(dpop);
            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        }
        assertThat(probe.calls.get()).isZero();
    }

    @Test
    void missingDuplicateAndOversizedDpopAreBadRequests() throws Exception {
        mvc.perform(request()).andExpect(status().isBadRequest());
        mvc.perform(request().header("DPoP", proof(URI), proof(URI))).andExpect(status().isBadRequest());
        mvc.perform(request().header("DPoP", "p".repeat(4097))).andExpect(status().isBadRequest());
        assertThat(probe.calls.get()).isZero();
    }

    @Test
    void proofFromPreviousRequestCannotAuthenticateTheNextRequest() throws Exception {
        mvc.perform(request().header("DPoP", proof(URI))).andExpect(status().isOk());
        mvc.perform(post(PATH).secure(true).contentType(MediaType.APPLICATION_JSON).content("{}")
                        .header("DPoP", proof(URI)))
                .andExpect(status().isForbidden());
        assertThat(probe.calls.get()).isEqualTo(1);
    }

    @Test
    void disabledNonProductionModeSkipsSignatureAndHttpBindingButRetainsKeyAndWorkloadChecks() throws Exception {
        context.close();
        startContext(true);
        var unsignedBinding = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().jwtID("dev-proof").issueTime(Date.from(NOW.minusSeconds(600)))
                        .claim("htm", "GET").claim("htu", "https://other.example/wrong")
                        .claim("nonce", "wrong-nonce").claim("ath", "wrong-hash").build());
        unsignedBinding.sign(new ECDSASigner(new ECKeyGenerator(Curve.P_256).generate()));
        mvc.perform(request().header("DPoP", unsignedBinding.serialize())).andExpect(status().isOk());
        assertThat(probe.verified.verification()).isEqualTo(VerifiedDpopProof.Verification.DISABLED_FOR_NON_PRODUCTION);
        assertThat(probe.verified.publicJwk()).isEqualTo(key.toPublicJWK().toJSONString());
        mvc.perform(request().header("DPoP", unsignedBinding.serialize()).secure(false))
                .andExpect(status().isForbidden());
        mvc.perform(request()).andExpect(status().isBadRequest());
        mvc.perform(request().header("DPoP", "p".repeat(64))).andExpect(status().isUnauthorized());
        assertThat(probe.calls.get()).isEqualTo(1);
    }

    private MockHttpServletRequestBuilder request() throws Exception {
        return post(PATH).secure(true).contentType(MediaType.APPLICATION_JSON).content("{}")
                .requestAttr("jakarta.servlet.request.X509Certificate", certificates(6, WORKLOAD));
    }

    private X509Certificate[] certificates(int type, String name) throws Exception {
        var certificate = mock(X509Certificate.class);
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(List.of(type, name)));
        return new X509Certificate[]{certificate};
    }

    private String proof(String uri) throws Exception {
        var proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().jwtID("proof-test-only").issueTime(Date.from(NOW))
                        .claim("htm", "POST").claim("htu", uri).build());
        proof.sign(new ECDSASigner(key));
        return proof.serialize();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @Import({SecurityConfiguration.class, DpopConfiguration.class})
    static class TestConfiguration {
        @Bean IngressProperties ingress() { return new IngressProperties("https://api.bank.example", Set.of(WORKLOAD)); }
        @Bean ExternalUriPolicy externalUris() { return new ExternalUriPolicy("https://api.bank.example"); }
        @Bean Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
        @Bean JsonMapper json() { return new JsonMapper(); }
        @Bean Sha256Digests digests() { return new Sha256Digests(); }
        @Bean StrictJoseJson strictJson() { return new StrictJoseJson(); }
        @Bean Probe probe() { return new Probe(); }
    }

    @RestController
    static class Probe {
        private final AtomicInteger calls = new AtomicInteger();
        private VerifiedDpopProof verified;
        private String workload;

        @PostMapping(PATH)
        Map<String, String> password(@RequestAttribute(DpopRequestAttributes.VERIFIED_DPOP_PROOF) VerifiedDpopProof proof,
                                     @RequestBody Map<String, Object> body, Authentication authentication) {
            calls.incrementAndGet();
            verified = proof;
            workload = authentication.getName();
            return Map.of("status", "checked");
        }
    }
}
