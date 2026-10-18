package com.vpbank.dcp.infrastructure.adapter.out.mfa;

import com.vpbank.dcp.core.port.out.mfa.MfaCheckResult;
import com.vpbank.dcp.core.port.out.mfa.MfaStartResult;
import com.vpbank.dcp.core.port.out.mfa.MfaTransactions;
import com.vpbank.dcp.core.port.out.mfa.MfaTrustCheck;
import com.vpbank.dcp.core.port.out.mfa.MfaTrustRequest;
import com.vpbank.dcp.core.port.out.mfa.MfaUnavailableException;
import com.vpbank.dcp.core.port.out.mfa.InvalidMfaTransactionException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.JcsCommandDigest;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.MfaReceiptVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpClient;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpRequestFailedException;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/**
 * Gives MFA status codes and receipts their meaning. {@code contextDigest} is the RFC 8785 digest
 * of the create body without itself; Auth recomputes it on check instead of storing it.
 */
public final class MfaTransactionsAdapter implements MfaTransactions {
    static final String PURPOSE = "TRUST_DEVICE";
    private static final List<String> FACTORS = List.of("FACE");

    private final MfaHttpClient http;
    private final MfaReceiptVerifier receipts;
    private final JcsCommandDigest canonicalDigest;
    private final JsonMapper json;
    private final Clock clock;

    public MfaTransactionsAdapter(MfaHttpClient http, MfaReceiptVerifier receipts,
                                  JcsCommandDigest canonicalDigest, JsonMapper json, Clock clock) {
        this.http = Objects.requireNonNull(http);
        this.receipts = Objects.requireNonNull(receipts);
        this.canonicalDigest = Objects.requireNonNull(canonicalDigest);
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public MfaStartResult start(MfaTrustRequest request) {
        Objects.requireNonNull(request);
        String digest = contextDigest(request);
        ExternalHttpClient.Response<MfaCreateResponse, MfaErrorResponse> reply;
        try {
            reply = http.create(new MfaCreateRequest(PURPOSE, request.customerNumber().value(),
                    request.channel(), request.authOperationId().toString(), FACTORS,
                    request.notAfter().toString(), digest));
        } catch (ExternalHttpRequestFailedException failure) {
            throw new MfaUnavailableException(failure);
        }
        if (!reply.isSuccess()) {
            // 409 means the same operation ID arrived with a different body: an Auth defect.
            if (reply.status() == 422 && "NO_USABLE_FACTOR".equals(reply.errorBody().code())) {
                return new MfaStartResult.NoUsableFactor();
            }
            throw new MfaUnavailableException();
        }
        MfaCreateResponse created = reply.successBody();
        try {
            return new MfaStartResult.Started(created.mfaTransactionId(),
                    Instant.parse(created.expiresAt()));
        } catch (InvalidMfaTransactionException | DateTimeParseException | NullPointerException bad) {
            throw new MfaUnavailableException(bad);
        }
    }

    @Override
    public MfaCheckResult check(MfaTrustCheck check) {
        Objects.requireNonNull(check);
        MfaTrustRequest request = check.request();
        String digest = contextDigest(request);
        ExternalHttpClient.Response<MfaCheckResponse, MfaErrorResponse> reply;
        try {
            reply = http.check(check.mfaTransactionId(),
                    new MfaCheckRequest(request.authOperationId().toString(), digest));
        } catch (ExternalHttpRequestFailedException failure) {
            throw new MfaUnavailableException(failure);
        }
        if (!reply.isSuccess()) {
            if (reply.status() == 404) {
                return new MfaCheckResult.Expired();
            }
            throw new MfaUnavailableException();
        }
        MfaReceiptVerifier.VerifiedMfaReceipt receipt;
        try {
            receipt = receipts.verify(reply.successBody().receipt(), clock.instant());
        } catch (InvalidCryptographicInputException | NullPointerException forged) {
            return new MfaCheckResult.InvalidReceipt();
        }
        if (!check.mfaTransactionId().equals(receipt.transactionId())
                || !request.authOperationId().toString().equals(receipt.authOperationId())
                || !PURPOSE.equals(receipt.purpose())
                || !request.customerNumber().value().equals(receipt.customerNumber())
                || !digest.equals(receipt.contextDigest())) {
            return new MfaCheckResult.InvalidReceipt();
        }
        return switch (receipt.status()) {
            case "PASSED" -> new MfaCheckResult.Passed(receipt.receiptDigest());
            case "PENDING" -> new MfaCheckResult.Pending();
            case "FAILED" -> new MfaCheckResult.Failed();
            case "EXPIRED" -> new MfaCheckResult.Expired();
            // The verifier admits only the four statuses above.
            default -> new MfaCheckResult.InvalidReceipt();
        };
    }

    private String contextDigest(MfaTrustRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("purpose", PURPOSE);
        body.put("customerNumber", request.customerNumber().value());
        body.put("channel", request.channel());
        body.put("authOperationId", request.authOperationId().toString());
        body.put("factors", FACTORS);
        body.put("notAfter", request.notAfter().toString());
        try {
            return canonicalDigest.ofCommand(json.writeValueAsString(body)).base64Url();
        } catch (JacksonException failure) {
            throw new InvalidMfaTransactionException();
        }
    }
}
