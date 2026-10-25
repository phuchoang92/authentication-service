package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CheckResult;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort.CreateResult;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class HttpMfaTransactionAdapterTest {
    private static final String BASE = "https://mfa.test";
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final EnrollmentId OP = EnrollmentId.random();
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final String DIGEST = "ctx-digest";
    private static final ECKey KEY = generate("mfa-receipt-1");
    private static final ECKey OTHER = generate("other");

    private final RestClient.Builder builder = RestClient.builder().baseUrl(BASE);
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final HttpMfaTransactionAdapter mfa = new HttpMfaTransactionAdapter(builder.build(),
            new MfaReceiptVerifier(KEY.toPublicJWK(), "mfa-service", Clock.fixed(NOW, ZoneOffset.UTC)), id -> ALICE);
    private final MfaTransactionRequest request = MfaTransactionRequest.builder().customerId(ALICE).channel(Channel.MOBILE)
            .authOperationId(OP).notAfter(NOW.plusSeconds(600)).contextDigest(DIGEST).build();

    @Test
    void createsAFaceTransactionBoundToTheEnrollmentAndAcceptsTheIdempotentReplay() {
        server.expect(requestTo(BASE + "/internal/v1/transactions")).andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.purpose").value("TRUST_DEVICE"))
                .andExpect(jsonPath("$.customerNumber").value("90359"))
                .andExpect(jsonPath("$.channel").value("MOBILE"))
                .andExpect(jsonPath("$.authOperationId").value(OP.toString()))
                .andExpect(jsonPath("$.factors[0]").value("FACE"))
                .andExpect(jsonPath("$.contextDigest").value(DIGEST))
                .andRespond(withStatus(HttpStatus.CREATED).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"success\":true,\"data\":{\"mfaTransactionId\":\"mfa-1\",\"expiresAt\":\"2026-10-25T10:05:00Z\"}}"));
        assertThat(mfa.create(request)).isEqualTo(new CreateResult.Created("mfa-1", Instant.parse("2026-10-25T10:05:00Z")));

        server.reset();
        server.expect(requestTo(BASE + "/internal/v1/transactions")).andRespond(withSuccess(
                "{\"success\":true,\"data\":{\"mfaTransactionId\":\"mfa-1\",\"expiresAt\":\"2026-10-25T10:05:00Z\"}}", MediaType.APPLICATION_JSON));
        assertThat(mfa.create(request)).isInstanceOf(CreateResult.Created.class);
    }

    @Test
    void noUsableFactorIsAResultWhileContractErrorsAndOutagesAreUnavailable() {
        server.expect(requestTo(BASE + "/internal/v1/transactions")).andRespond(withStatus(HttpStatus.UNPROCESSABLE_ENTITY)
                .contentType(MediaType.APPLICATION_JSON).body("{\"success\":false,\"error\":{\"code\":\"NO_USABLE_FACTOR\"}}"));
        assertThat(mfa.create(request)).isInstanceOf(CreateResult.NoUsableFactor.class);

        for (Consumer<MockRestServiceServer> failure : java.util.List.<Consumer<MockRestServiceServer>>of(
                s -> s.expect(requestTo(BASE + "/internal/v1/transactions")).andRespond(withStatus(HttpStatus.CONFLICT)),
                s -> s.expect(requestTo(BASE + "/internal/v1/transactions")).andRespond(withStatus(HttpStatus.BAD_GATEWAY)),
                s -> s.expect(requestTo(BASE + "/internal/v1/transactions")).andRespond(withException(new SocketTimeoutException("slow"))),
                s -> s.expect(requestTo(BASE + "/internal/v1/transactions")).andRespond(withSuccess("{\"success\":true,\"data\":{}}", MediaType.APPLICATION_JSON)))) {
            server.reset();
            failure.accept(server);
            assertThatThrownBy(() -> mfa.create(request)).isInstanceOf(PartnerUnavailableException.class);
        }
    }

    @Test
    void checkVerifiesTheSignedReceiptAndMapsEveryStatus() throws Exception {
        expectCheck(receipt(KEY, "PASSED", Map.of("factor", "FACE", "verifiedAt", "2026-10-25T09:59:50Z")));
        CheckResult passed = mfa.check("mfa-1", OP, DIGEST);
        assertThat(passed).isInstanceOf(CheckResult.Passed.class);
        assertThat(((CheckResult.Passed) passed).receiptDigest()).hasSize(43);

        server.reset();
        expectCheck(receipt(KEY, "PENDING", Map.of()));
        assertThat(mfa.check("mfa-1", OP, DIGEST)).isInstanceOf(CheckResult.Pending.class);
        server.reset();
        expectCheck(receipt(KEY, "FAILED", Map.of()));
        assertThat(mfa.check("mfa-1", OP, DIGEST)).isInstanceOf(CheckResult.Failed.class);
        server.reset();
        expectCheck(receipt(KEY, "EXPIRED", Map.of()));
        assertThat(mfa.check("mfa-1", OP, DIGEST)).isInstanceOf(CheckResult.Expired.class);
        server.reset();
        server.expect(requestTo(BASE + "/internal/v1/transactions/mfa-1/check")).andRespond(withStatus(HttpStatus.NOT_FOUND));
        assertThat(mfa.check("mfa-1", OP, DIGEST)).isInstanceOf(CheckResult.Expired.class);
    }

    @Test
    void aReceiptFromAnotherKeyForAnotherOperationOrWithExtraClaimsIsRejectedNeverPending() throws Exception {
        for (String bad : java.util.List.of(
                receipt(OTHER, "PASSED", Map.of("factor", "FACE", "verifiedAt", "x")),
                receipt(KEY, "PASSED", Map.of("factor", "FACE", "verifiedAt", "x", "extra", "1")),
                receipt(KEY, "PASSED", Map.of()),                                  // PASSED without factor
                receipt(KEY, "PENDING", Map.of("op", "someone-else")),
                receipt(KEY, "PENDING", Map.of("customerNumber", "77777")),
                receipt(KEY, "PENDING", Map.of("contextDigest", "other")),
                receipt(KEY, "PENDING", Map.of("aud", "someone")),
                receipt(KEY, "PASSED", Map.of("factor", "SMS", "verifiedAt", "x")))) {
            server.reset();
            expectCheck(bad);
            assertThat(mfa.check("mfa-1", OP, DIGEST)).as(bad).isInstanceOf(CheckResult.Rejected.class);
        }
        server.reset();
        server.expect(requestTo(BASE + "/internal/v1/transactions/mfa-1/check")).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        assertThatThrownBy(() -> mfa.check("mfa-1", OP, DIGEST)).isInstanceOf(PartnerUnavailableException.class);
    }

    private void expectCheck(String receipt) {
        server.expect(requestTo(BASE + "/internal/v1/transactions/mfa-1/check")).andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.authOperationId").value(OP.toString()))
                .andExpect(jsonPath("$.contextDigest").value(DIGEST))
                .andRespond(withSuccess("{\"success\":true,\"data\":{\"receipt\":\"" + receipt + "\"}}", MediaType.APPLICATION_JSON));
    }

    private static String receipt(ECKey key, String status, Map<String, Object> overrides) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer("mfa-service").audience("authentication-service")
                .claim("txn", "mfa-1").claim("op", OP.toString()).claim("purpose", "TRUST_DEVICE")
                .claim("customerNumber", "90359").claim("contextDigest", DIGEST).claim("status", status)
                .issueTime(Date.from(NOW.minusSeconds(1))).expirationTime(Date.from(NOW.plusSeconds(30))).jwtID("jti-" + status);
        overrides.forEach(claims::claim);
        SignedJWT jws = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims.build());
        jws.sign(new ECDSASigner(key));
        return jws.serialize();
    }

    private static ECKey generate(String kid) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
