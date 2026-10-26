package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.MfaTransactionPort;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CheckTransactionRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CheckTransactionResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CreateTransactionRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CreateTransactionResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.mapper.MfaTransactionMapper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * The MFA service over HTTP (DD 20 §5, assumed contract until the MFA team confirms). {@code create}
 * is idempotent on {@code authOperationId} (201 new, 200 same request again); 422 = no FACE factor;
 * any other 4xx is a contract error and fails closed. {@code check} reads the signed receipt; 404 =
 * the transaction expired. 5xx and timeouts are unavailable; Auth never retries here.
 *
 * <p>The customer number is needed to verify the receipt's binding, so it travels with the check.
 */
@RequiredArgsConstructor
public final class HttpMfaTransactionAdapter implements MfaTransactionPort {
    private static final String PARTNER = "MFA service";
    private static final String TRANSACTIONS_PATH = "/internal/v1/transactions";
    private static final String CHECK_PATH = "/internal/v1/transactions/{id}/check";
    private static final String NO_USABLE_FACTOR = "NO_USABLE_FACTOR";
    private static final int OK = 200;
    private static final int CREATED = 201;
    private static final int NOT_FOUND = 404;
    private static final int UNPROCESSABLE = 422;

    @NonNull private final RestClient restClient;
    @NonNull private final MfaReceiptVerifier mfaReceiptVerifier;
    @NonNull private final CustomerLookup enrollmentCustomerLookup;

    /** Resolves the customer behind an enrollment for the receipt check; wired from the enrollment repository. */
    public interface CustomerLookup {
        CustomerId customerOf(EnrollmentId authOperationId);
    }

    @Override
    public CreateResult create(MfaTransactionRequest mfaTransactionRequest) {
        CreateTransactionRequest createTransactionRequest = MfaTransactionMapper.toCreate(mfaTransactionRequest);
        try {
            return restClient.post()
                    .uri(TRANSACTIONS_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(createTransactionRequest)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        CreateTransactionResponse createResponse = response.bodyTo(CreateTransactionResponse.class);

                        boolean noUsableFactor = createResponse != null
                                && createResponse.error() != null
                                && NO_USABLE_FACTOR.equals(createResponse.error().code());
                        if (status == UNPROCESSABLE && noUsableFactor) {
                            return new CreateResult.NoUsableFactor();
                        }

                        boolean createdOrRepeated = status == OK || status == CREATED;
                        boolean hasTransaction = createResponse != null
                                && createResponse.data() != null
                                && createResponse.data().mfaTransactionId() != null
                                && createResponse.data().expiresAt() != null;
                        if (!createdOrRepeated || !hasTransaction) {
                            throw new PartnerUnavailableException(PARTNER);
                        }

                        return new CreateResult.Created(
                                createResponse.data().mfaTransactionId(),
                                createResponse.data().expiresAt());
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }

    @Override
    public CheckResult check(MfaCheckRequest mfaCheckRequest) {
        CheckTransactionRequest checkTransactionRequest = MfaTransactionMapper.toCheck(mfaCheckRequest);
        try {
            return restClient.post()
                    .uri(CHECK_PATH, mfaCheckRequest.mfaTransactionId())
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(checkTransactionRequest)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status == NOT_FOUND) {
                            return new CheckResult.Expired();
                        }

                        CheckTransactionResponse checkResponse = response.bodyTo(CheckTransactionResponse.class);
                        boolean hasReceipt = checkResponse != null
                                && checkResponse.data() != null
                                && checkResponse.data().receipt() != null;
                        if (status != OK || !hasReceipt) {
                            throw new PartnerUnavailableException(PARTNER);
                        }

                        CustomerId customerId = enrollmentCustomerLookup.customerOf(mfaCheckRequest.authOperationId());
                        return mfaReceiptVerifier.verify(
                                checkResponse.data().receipt(),
                                mfaCheckRequest,
                                customerId);
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
