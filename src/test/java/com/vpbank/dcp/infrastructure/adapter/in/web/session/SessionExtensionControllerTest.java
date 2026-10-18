package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.session.ExtendSessionCommand;
import com.vpbank.dcp.core.session.ExtendSessionResult.Extended;
import com.vpbank.dcp.core.session.ExtendSessionResult.NotExtended;
import com.vpbank.dcp.core.session.ExtendSessionResult.Reason;
import com.vpbank.dcp.core.session.ExtendSessionService;
import com.vpbank.dcp.infrastructure.adapter.in.web.BoundedJsonBodyAdvice;
import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiErrorHandler;
import com.vpbank.dcp.infrastructure.config.properties.SessionExtensionProperties;
import java.security.Principal;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class SessionExtensionControllerTest {
    private static final String PATH = "/internal/v1/auth/sessions/extend";
    private static final String BFF = "spiffe://bank/mobile-bff";
    private static final String LOOKUP = "A".repeat(43);
    private static final String JKT = "B".repeat(42) + "A";
    private static final UUID ADMISSION = UUID.fromString("4cf11838-62df-4799-ac0a-6644a86188c5");
    private static final Instant ADMITTED = Instant.parse("2026-10-18T10:00:00.000Z");

    private final ExtendSessionService service = mock(ExtendSessionService.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new SessionExtensionController(service,
                    new SessionExtensionProperties(BFF, Set.of("accounts.read"), 30000, 2000)))
            .setControllerAdvice(new ApiErrorHandler(), new BoundedJsonBodyAdvice()).build();

    @Test
    void extendedSessionReturnsBothDeadlines() throws Exception {
        var deadlines = new SessionDeadlines(Instant.parse("2026-10-18T10:15:00Z"),
                Instant.parse("2026-10-18T10:18:00Z"));
        when(service.extend(any())).thenReturn(new Extended(deadlines));

        call(BFF, body(JKT, ADMITTED.toString()))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("EXTENDED"))
                .andExpect(jsonPath("$.idleExpiresAt").value("2026-10-18T10:15:00Z"))
                .andExpect(jsonPath("$.absoluteExpiresAt").value("2026-10-18T10:18:00Z"));

        ArgumentCaptor<ExtendSessionCommand> sent = ArgumentCaptor.forClass(ExtendSessionCommand.class);
        verify(service).extend(sent.capture());
        assertThat(sent.getValue()).isEqualTo(new ExtendSessionCommand(
                new SessionTokenLookup(new LookupKeyVersion("k1"), Digest32.fromBase64Url(LOOKUP)),
                new RequestKeyThumbprint(Digest32.fromBase64Url(JKT)), "accounts.read", ADMISSION,
                ADMITTED));
    }

    @Test
    void eachRefusalHasItsOwnStatusAndASafeBody() throws Exception {
        expect(Reason.INVALID_REQUEST, 400, "REQUEST_REJECTED");
        expect(Reason.GONE, 410, "SESSION_EXPIRED");
        expect(Reason.CONFLICT, 409, "SESSION_CHANGED");
        expect(Reason.UNAVAILABLE, 503, "TEMPORARILY_UNAVAILABLE");
    }

    @Test
    void anotherWorkloadIsForbidden() throws Exception {
        call("spiffe://bank/payments", body(JKT, ADMITTED.toString()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REQUEST_REJECTED"));
        verifyNoInteractions(service);
    }

    @Test
    void missingWorkloadIsForbidden() throws Exception {
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(body(JKT, ADMITTED.toString())))
                .andExpect(status().isForbidden());
        verifyNoInteractions(service);
    }

    @Test
    void malformedValuesAreRejectedBeforeTheService() throws Exception {
        call(BFF, body("short", ADMITTED.toString())).andExpect(status().isBadRequest());
        call(BFF, body(JKT, "yesterday")).andExpect(status().isBadRequest());
        // Matches the wire pattern but is not a canonical 32-byte base64url digest.
        call(BFF, body("B".repeat(43), ADMITTED.toString())).andExpect(status().isBadRequest());
        call(BFF, "{}").andExpect(status().isBadRequest());
        verifyNoInteractions(service);
    }

    private void expect(Reason reason, int status, String code) throws Exception {
        when(service.extend(any())).thenReturn(new NotExtended(reason));
        call(BFF, body(JKT, ADMITTED.toString()))
                .andExpect(status().is(status))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.code").value(code))
                .andExpect(jsonPath("$.correlationId").exists());
    }

    private ResultActions call(String workload, String json) throws Exception {
        Principal principal = () -> workload;
        return mvc.perform(post(PATH).principal(principal)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private static String body(String requestKeyJkt, String admittedAt) {
        return """
                {"sessionLookup":{"lookupKeyVersion":"k1","lookupDigest":"%s"},
                 "admissionId":"%s","admittedAt":"%s","routeId":"accounts.read",
                 "requestKeyJkt":"%s"}""".formatted(LOOKUP, ADMISSION, admittedAt, requestKeyJkt);
    }
}
