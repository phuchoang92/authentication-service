package com.vpbank.dcp.infrastructure.adapter.out.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.customer.CustomerNumber;
import com.vpbank.dcp.core.trusteddevice.MfaCheckResult;
import com.vpbank.dcp.core.trusteddevice.MfaStartResult;
import com.vpbank.dcp.core.trusteddevice.MfaTrustCheck;
import com.vpbank.dcp.core.trusteddevice.MfaTrustRequest;
import com.vpbank.dcp.core.trusteddevice.MfaUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.JcsCommandDigest;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.MfaReceiptVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.Sha256Digests;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.StrictJoseJson;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.databind.json.JsonMapper;

class MfaTransactionsAdapterTest {
    private static final Instant NOW = Instant.parse("2026-10-18T00:00:00Z");
    private static final String TXN = "mfa-transaction-0000000000001";
    private final MfaHttpClient http = mock(MfaHttpClient.class);
    private final ECKey mfaKey;
    private final MfaTransactionsAdapter adapter;
    private final MfaTrustRequest request = new MfaTrustRequest(UUID.randomUUID(),
            new CustomerNumber("CUST-1"), "neo-mobile", NOW.plusSeconds(600));

    MfaTransactionsAdapterTest() throws Exception {
        mfaKey = new ECKeyGenerator(Curve.P_256).keyID("mfa-receipt-v1").generate();
        adapter = new MfaTransactionsAdapter(http,
                new MfaReceiptVerifier("mfa-service", "mfa-receipt-v1", mfaKey.toPublicJWK(),
                        new StrictJoseJson(), new Sha256Digests()),
                new JcsCommandDigest(new StrictJoseJson(), new Sha256Digests()),
                JsonMapper.builder().build(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void startSendsOnlyTheCustomerNumberAndTheContextDigest() {
        ArgumentCaptor<MfaCreateRequest> sent = ArgumentCaptor.forClass(MfaCreateRequest.class);
        var reply = success(new MfaCreateResponse(TXN, NOW.plusSeconds(300).toString()), 201);
        when(http.create(sent.capture())).thenReturn(reply);

        assertThat(adapter.start(request))
                .isEqualTo(new MfaStartResult.Started(TXN, NOW.plusSeconds(300)));
        MfaCreateRequest body = sent.getValue();
        assertThat(body.purpose()).isEqualTo("TRUST_DEVICE");
        assertThat(body.customerNumber()).isEqualTo("CUST-1");
        assertThat(body.authOperationId()).isEqualTo(request.authOperationId().toString());
        assertThat(body.factors()).containsExactly("FACE");
        assertThat(body.contextDigest()).isEqualTo(digestOf(request));
    }

    @Test
    void customerWithoutFaceIsNoUsableFactor() {
        var reply = error(422, "NO_USABLE_FACTOR");
        when(http.create(any())).thenReturn(reply);

        assertThat(adapter.start(request)).isInstanceOf(MfaStartResult.NoUsableFactor.class);
    }

    /** A conflict or outage is never read as a missing factor or a started transaction. */
    @Test
    void conflictOutageOrTransportFailureIsUnavailable() {
        var conflict = error(409, "IDEMPOTENCY_CONFLICT");
        when(http.create(any())).thenReturn(conflict);
        assertThatThrownBy(() -> adapter.start(request)).isInstanceOf(MfaUnavailableException.class);

        var down = error(503, "UNAVAILABLE");
        when(http.create(any())).thenReturn(down);
        assertThatThrownBy(() -> adapter.start(request)).isInstanceOf(MfaUnavailableException.class);

        when(http.create(any())).thenThrow(new ExternalHttpRequestFailedException());
        assertThatThrownBy(() -> adapter.start(request)).isInstanceOf(MfaUnavailableException.class);
    }

    @Test
    void passedReceiptForThisTrustIsPassed() throws Exception {
        String receipt = receipt(claims("PASSED").claim("factor", "FACE")
                .claim("verifiedAt", NOW.toString()));
        checkReturns(receipt);

        MfaCheckResult result = adapter.check(new MfaTrustCheck(TXN, request));

        assertThat(result).isInstanceOf(MfaCheckResult.Passed.class);
        assertThat(((MfaCheckResult.Passed) result).receiptDigest())
                .isEqualTo(new Sha256Digests().sha256(receipt.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    }

    @Test
    void pendingReceiptIsPending() throws Exception {
        checkReturns(receipt(claims("PENDING")));

        assertThat(adapter.check(new MfaTrustCheck(TXN, request)))
                .isInstanceOf(MfaCheckResult.Pending.class);
    }

    /** A receipt for another customer, operation, transaction or context is a forgery here. */
    @Test
    void receiptForAnotherTrustIsInvalidAndNeverPending() throws Exception {
        for (JWTClaimsSet.Builder foreign : java.util.List.of(
                passed().claim("customerNumber", "CUST-2"),
                passed().claim("op", UUID.randomUUID().toString()),
                passed().claim("txn", "mfa-transaction-0000000000002"),
                passed().claim("contextDigest", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                passed().claim("purpose", "TRANSFER"))) {
            checkReturns(receipt(foreign));
            assertThat(adapter.check(new MfaTrustCheck(TXN, request)))
                    .isInstanceOf(MfaCheckResult.InvalidReceipt.class);
        }
    }

    @Test
    void receiptSignedByAnotherKeyOrWithExtraClaimsIsInvalid() throws Exception {
        ECKey attacker = new ECKeyGenerator(Curve.P_256).keyID("mfa-receipt-v1").generate();
        SignedJWT forged = new SignedJWT(header(), passed().build());
        forged.sign(new ECDSASigner(attacker));
        checkReturns(forged.serialize());
        assertThat(adapter.check(new MfaTrustCheck(TXN, request)))
                .isInstanceOf(MfaCheckResult.InvalidReceipt.class);

        checkReturns(receipt(passed().claim("scope", "banking")));
        assertThat(adapter.check(new MfaTrustCheck(TXN, request)))
                .isInstanceOf(MfaCheckResult.InvalidReceipt.class);

        checkReturns(receipt(claims("PASSED")));
        assertThat(adapter.check(new MfaTrustCheck(TXN, request)))
                .isInstanceOf(MfaCheckResult.InvalidReceipt.class);
    }

    @Test
    void unknownTransactionIsExpiredAndOutageIsUnavailable() {
        var missing = checkError(404, "NOT_FOUND");
        when(http.check(eq(TXN), any())).thenReturn(missing);
        assertThat(adapter.check(new MfaTrustCheck(TXN, request)))
                .isInstanceOf(MfaCheckResult.Expired.class);

        var down = checkError(503, "UNAVAILABLE");
        when(http.check(eq(TXN), any())).thenReturn(down);
        assertThatThrownBy(() -> adapter.check(new MfaTrustCheck(TXN, request)))
                .isInstanceOf(MfaUnavailableException.class);
    }

    private JWTClaimsSet.Builder passed() {
        return claims("PASSED").claim("factor", "FACE").claim("verifiedAt", NOW.toString());
    }

    private JWTClaimsSet.Builder claims(String status) {
        return new JWTClaimsSet.Builder().issuer("mfa-service").audience("authentication-service")
                .claim("txn", TXN).claim("op", request.authOperationId().toString())
                .claim("purpose", "TRUST_DEVICE").claim("customerNumber", "CUST-1")
                .claim("contextDigest", digestOf(request)).claim("status", status)
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(30)))
                .jwtID(UUID.randomUUID().toString());
    }

    private JWSHeader header() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("mfa-receipt-v1")
                .type(new JOSEObjectType("mfa-receipt+jwt")).build();
    }

    private String receipt(JWTClaimsSet.Builder claims) throws Exception {
        SignedJWT jwt = new SignedJWT(header(), claims.build());
        jwt.sign(new ECDSASigner(mfaKey));
        return jwt.serialize();
    }

    private String digestOf(MfaTrustRequest trust) {
        String canonical = "{\"authOperationId\":\"" + trust.authOperationId() + "\","
                + "\"channel\":\"neo-mobile\",\"customerNumber\":\"CUST-1\","
                + "\"factors\":[\"FACE\"],\"notAfter\":\"" + trust.notAfter() + "\","
                + "\"purpose\":\"TRUST_DEVICE\"}";
        return new Sha256Digests().sha256(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .base64Url();
    }

    private void checkReturns(String receipt) {
        @SuppressWarnings("unchecked")
        ExternalHttpClient.Response<MfaCheckResponse, MfaErrorResponse> reply =
                mock(ExternalHttpClient.Response.class);
        when(reply.isSuccess()).thenReturn(true);
        when(reply.status()).thenReturn(200);
        when(reply.successBody()).thenReturn(new MfaCheckResponse(receipt));
        when(http.check(eq(TXN), any())).thenReturn(reply);
    }

    @SuppressWarnings("unchecked")
    private ExternalHttpClient.Response<MfaCheckResponse, MfaErrorResponse> checkError(int status,
                                                                                     String code) {
        ExternalHttpClient.Response<MfaCheckResponse, MfaErrorResponse> reply =
                mock(ExternalHttpClient.Response.class);
        when(reply.isSuccess()).thenReturn(false);
        when(reply.status()).thenReturn(status);
        when(reply.errorBody()).thenReturn(new MfaErrorResponse(code));
        return reply;
    }

    @SuppressWarnings("unchecked")
    private static ExternalHttpClient.Response<MfaCreateResponse, MfaErrorResponse> success(
            MfaCreateResponse body, int status) {
        ExternalHttpClient.Response<MfaCreateResponse, MfaErrorResponse> reply =
                mock(ExternalHttpClient.Response.class);
        when(reply.isSuccess()).thenReturn(true);
        when(reply.status()).thenReturn(status);
        when(reply.successBody()).thenReturn(body);
        return reply;
    }

    @SuppressWarnings("unchecked")
    private static ExternalHttpClient.Response<MfaCreateResponse, MfaErrorResponse> error(int status,
                                                                                        String code) {
        ExternalHttpClient.Response<MfaCreateResponse, MfaErrorResponse> reply =
                mock(ExternalHttpClient.Response.class);
        when(reply.isSuccess()).thenReturn(false);
        when(reply.status()).thenReturn(status);
        when(reply.errorBody()).thenReturn(new MfaErrorResponse(code));
        return reply;
    }
}
