package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.port.in.IssueServiceTokenUseCase;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.BusinessReference;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceTokenPublicKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.VerifiedServiceClient;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.ServiceTokenRestMapper;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Instant;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/** The web slice of slice 12: envelope, validation, status table and the bare JWKS document; the use case is mocked. */
@WebMvcTest(controllers = {ServiceTokenController.class, ServiceTokenJwksController.class},
        properties = "auth.service-token.enabled=true")
@Import({RestConfiguration.class, ServiceTokenControllerTest.Beans.class})
class ServiceTokenControllerTest {
    private static final ECKey SIGNING_KEY = generate();
    private static final VerifiedServiceClient ONBOARDING =
            new VerifiedServiceClient(new ServiceId("onboarding-service"));
    private static final Instant EXPIRES = Instant.parse("2026-11-03T10:15:00Z");

    @TestConfiguration
    static class Beans {
        @Bean
        ServiceTokenRestMapper serviceTokenRestMapper(ErrorMessages errors) {
            return new ServiceTokenRestMapper(errors);
        }

        @Bean
        ServiceTokenPublicKeys serviceTokenPublicKeys() {
            return ServiceTokenPublicKeys.of(List.of(SIGNING_KEY));
        }
    }

    @Autowired MockMvc mvc;
    @MockitoBean IssueServiceTokenUseCase service;

    @Test
    void anIssuedTokenIs200InTheEnvelope() throws Exception {
        when(service.issue(any())).thenReturn(new IssueServiceTokenResult.Issued("a.b.c", ServiceScope.ONBOARDING, EXPIRES));

        issue("{\"scope\":\"onboarding\",\"businessReference\":\"onb-1\"}").andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("X-Correlation-Id", Matchers.matchesPattern("[0-9a-f-]{36}")))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.token").value("a.b.c"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.scope").value("onboarding"))
                .andExpect(jsonPath("$.data.expiresAt").value("2026-11-03T10:15:00Z"))
                .andExpect(jsonPath("$.error").doesNotExist());
        verify(service).issue(new IssueServiceTokenCommand(new ServiceId("onboarding-service"), ServiceScope.ONBOARDING,
                new BusinessReference("onb-1")));
    }

    @Test
    void refusedScopeAndMissingReferenceFollowTheStatusTable() throws Exception {
        when(service.issue(any())).thenReturn(new IssueServiceTokenResult.ScopeNotAllowed());
        issue("{\"scope\":\"onboarding\",\"businessReference\":\"onb-1\"}").andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("SCOPE_NOT_ALLOWED"))
                .andExpect(jsonPath("$.error.message").value("Dịch vụ gọi không được phép yêu cầu phạm vi này"));

        when(service.issue(any())).thenReturn(new IssueServiceTokenResult.BusinessReferenceRequired());
        issue("{\"scope\":\"onboarding\"}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"));
    }

    @Test
    void aBadBodyOrAnUnknownScopeIs400BeforeTheUseCase() throws Exception {
        issue("{}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.error.details[0].field").value("scope"));
        issue("{\"scope\":\"onboarding\",\"businessReference\":\"has space\"}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.details[0].field").value("businessReference"));
        issue("{\"scope\":\"banking\"}").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"));
        verifyNoInteractions(service);
    }

    @Test
    void theJwksRouteServesTheBarePublicKeySet() throws Exception {
        mvc.perform(get(ServiceTokenJwksController.JWKS_PATH)).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys[0].kid").value("svc-test-1"))
                .andExpect(jsonPath("$.keys[0].kty").value("EC"))
                .andExpect(jsonPath("$.keys[0].crv").value("P-256"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.success").doesNotExist());
    }

    private ResultActions issue(String body) throws Exception {
        return mvc.perform(post(ServiceClientAssertionFilter.ISSUE_PATH)
                .requestAttr(ServiceClientAssertionFilter.CALLING_SERVICE_ATTRIBUTE, ONBOARDING)
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("svc-test-1").generate();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }
}
