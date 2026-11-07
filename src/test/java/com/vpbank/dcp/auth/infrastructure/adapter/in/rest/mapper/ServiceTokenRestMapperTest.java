package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ApiEnvelope;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.InvalidRequestException;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.VerifiedServiceClient;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.request.IssueServiceTokenRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.dto.response.ServiceTokenResponse;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class ServiceTokenRestMapperTest {
    private static final VerifiedServiceClient ONBOARDING =
            new VerifiedServiceClient(new ServiceId("onboarding-service"));
    private static final Instant EXPIRES = Instant.parse("2026-11-03T10:15:00Z");
    private final ServiceTokenRestMapper mapper = new ServiceTokenRestMapper(new ErrorMessages(RestConfiguration.errorMessageSource()));

    @Test
    void theCallerComesFromTheFilterAndTheScopeFromItsWireCode() {
        IssueServiceTokenCommand command = mapper.toCommand(ONBOARDING, new IssueServiceTokenRequest("onboarding", "onb-1"));

        assertThat(command).isEqualTo(new IssueServiceTokenCommand(new ServiceId("onboarding-service"),
                ServiceScope.ONBOARDING, new BusinessReference("onb-1")));
        assertThat(mapper.toCommand(ONBOARDING, new IssueServiceTokenRequest("onboarding", null)).businessReference()).isNull();
        assertThat(mapper.toCommand(ONBOARDING, new IssueServiceTokenRequest("onboarding", "")).businessReference()).isNull();
    }

    @Test
    void anUnknownScopeIsABadRequest() {
        assertThatThrownBy(() -> mapper.toCommand(ONBOARDING, new IssueServiceTokenRequest("ONBOARDING", null)))
                .isInstanceOf(InvalidRequestException.class);
        assertThatThrownBy(() -> mapper.toCommand(ONBOARDING, new IssueServiceTokenRequest("banking", null)))
                .isInstanceOf(InvalidRequestException.class);
    }

    @Test
    void resultsMapToTheStatusTable() {
        ResponseEntity<ApiEnvelope<ServiceTokenResponse>> issued = mapper.toResponse(
                new IssueServiceTokenResult.Issued("a.b.c", ServiceScope.ONBOARDING, EXPIRES));
        assertThat(issued.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(issued.getBody().data()).isEqualTo(new ServiceTokenResponse("a.b.c", "Bearer", "onboarding", EXPIRES));
        assertThat(issued.getBody().data().toString()).doesNotContain("a.b.c");

        ResponseEntity<ApiEnvelope<ServiceTokenResponse>> refused = mapper.toResponse(new IssueServiceTokenResult.ScopeNotAllowed());
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(refused.getBody().error().code()).isEqualTo("SCOPE_NOT_ALLOWED");

        ResponseEntity<ApiEnvelope<ServiceTokenResponse>> incomplete = mapper.toResponse(new IssueServiceTokenResult.BusinessReferenceRequired());
        assertThat(incomplete.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(incomplete.getBody().error().code()).isEqualTo("REQUEST_REJECTED");
    }
}
