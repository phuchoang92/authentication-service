package com.vpbank.dcp.auth.infrastructure.adapter.in.web.registration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.auth.core.customer.CustomerRegistrationService;
import com.vpbank.dcp.auth.core.customer.RegistrationCommand;
import com.vpbank.dcp.auth.core.customer.RegistrationResult;
import com.vpbank.dcp.auth.infrastructure.adapter.in.web.ApiErrorHandler;
import com.vpbank.dcp.auth.infrastructure.adapter.in.web.ResponseHeadersFilter;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

class RegistrationControllerTest {
    private static final String PATH = "/internal/v1/callback/authentication-creation";
    private static final UUID REQUEST = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final String BODY = """
            {"customerId":"90359","userName":"alice","firstName":"Alice","lastName":"Nguyen",
             "phoneNumber":"+84901234567","email":"alice@example.com"}""";

    private final CustomerRegistrationService service = mock(CustomerRegistrationService.class);
    private final MockMvc mvc;

    RegistrationControllerTest() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();
        mvc = MockMvcBuilders.standaloneSetup(new RegistrationController(service))
                .setControllerAdvice(new ApiErrorHandler())
                .setValidator(validator)
                .addFilters(new ResponseHeadersFilter())
                .build();
    }

    @Test
    void aNewAccountIs201WithTheEnvelopeAndHeaders() throws Exception {
        when(service.register(any())).thenReturn(new RegistrationResult.Ready(REQUEST, "90359", "alice", true));

        call(BODY).andExpect(status().isCreated())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("X-Correlation-Id", Matchers.matchesPattern("[0-9a-f-]{36}")))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.requestId").value(REQUEST.toString()))
                .andExpect(jsonPath("$.data.customerId").value("90359"))
                .andExpect(jsonPath("$.data.userName").value("alice"))
                .andExpect(jsonPath("$.data.state").value("READY"))
                .andExpect(jsonPath("$.error").doesNotExist());
        verify(service).register(new RegistrationCommand("90359", "alice", "Alice", "Nguyen", "+84901234567",
                "alice@example.com"));
    }

    @Test
    void aRepeatOfAReadyAccountIs200() throws Exception {
        when(service.register(any())).thenReturn(new RegistrationResult.Ready(REQUEST, "90359", "alice", false));

        call(BODY).andExpect(status().isOk()).andExpect(jsonPath("$.data.state").value("READY"));
    }

    @Test
    void eachRefusalHasItsStatusAndCode() throws Exception {
        expect(new RegistrationResult.IdentityConflict(), 409, "IDENTITY_CONFLICT");
        expect(new RegistrationResult.ProfileIncomplete(), 409, "CUSTOMER_PROFILE_INCOMPLETE");
        expect(new RegistrationResult.Unavailable(), 503, "ACCOUNT_CREATION_UNAVAILABLE");
    }

    @Test
    void invalidFieldsAre400WithFieldNamesButNoValues() throws Exception {
        String bad = BODY.replace("+84901234567", "0901234567").replace("\"alice\"", "\"a\"");

        call(bad).andExpect(status().isBadRequest())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.error.details[0].field").value("phoneNumber"))
                .andExpect(jsonPath("$.error.details[0].message").value("must match the required format"))
                .andExpect(jsonPath("$.error.details[1].field").value("userName"))
                .andExpect(jsonPath("$..value").doesNotExist())
                .andExpect(jsonPath("$.data").doesNotExist());
        verifyNoInteractions(service);
    }

    @Test
    void anUnreadableBodyIs400() throws Exception {
        call("{not json").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.error.details").isEmpty());
    }

    private void expect(RegistrationResult result, int status, String code) throws Exception {
        when(service.register(any())).thenReturn(result);
        call(BODY).andExpect(status().is(status))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value(code))
                .andExpect(jsonPath("$.error.details").isEmpty());
    }

    private ResultActions call(String json) throws Exception {
        return mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json));
    }
}
