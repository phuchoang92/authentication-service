package com.vpbank.dcp.auth.adapter.in.web.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.vpbank.dcp.auth.application.port.in.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerResult;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerUseCase;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import com.vpbank.dcp.auth.adapter.in.web.common.ErrorMessages;
import com.vpbank.dcp.auth.adapter.in.web.common.GlobalExceptionHandler;
import com.vpbank.dcp.auth.adapter.in.web.common.ResponseHeadersFilter;
import com.vpbank.dcp.auth.adapter.in.web.mapper.RegistrationWebMapper;
import com.vpbank.dcp.auth.config.WebConfiguration;
import org.springframework.context.MessageSource;
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
    private static final RegistrationId REQUEST =
            new RegistrationId(UUID.fromString("22222222-2222-4222-8222-222222222222"));
    private static final CustomerId CUSTOMER = new CustomerId("90359");
    private static final UserName ALICE = new UserName("alice");
    private static final String BODY = """
            {"customerId":"90359","userName":"alice","firstName":"Alice","lastName":"Nguyen",
             "phoneNumber":"+84901234567","email":"alice@example.com"}""";

    private final RegisterCustomerUseCase service = mock(RegisterCustomerUseCase.class);
    private final MockMvc mvc;

    RegistrationControllerTest() {
        MessageSource messages = WebConfiguration.errorMessageSource();
        ErrorMessages errors = new ErrorMessages(messages);
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.setValidationMessageSource(messages);
        validator.afterPropertiesSet();
        mvc = MockMvcBuilders.standaloneSetup(new RegistrationController(service, new RegistrationWebMapper(errors)))
                .setControllerAdvice(new GlobalExceptionHandler(errors))
                .setValidator(validator)
                .setLocaleResolver(WebConfiguration.acceptHeaderLocaleResolver())
                .addFilters(new ResponseHeadersFilter())
                .build();
    }

    @Test
    void aNewAccountIs201WithTheEnvelopeAndHeaders() throws Exception {
        when(service.register(any())).thenReturn(new RegisterCustomerResult.Ready(REQUEST, CUSTOMER, ALICE, true));

        call(BODY).andExpect(status().isCreated())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("X-Correlation-Id", Matchers.matchesPattern("[0-9a-f-]{36}")))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.requestId").value(REQUEST.toString()))
                .andExpect(jsonPath("$.data.customerId").value("90359"))
                .andExpect(jsonPath("$.data.userName").value("alice"))
                .andExpect(jsonPath("$.data.state").value("READY"))
                .andExpect(jsonPath("$.error").doesNotExist());
        verify(service).register(RegisterCustomerCommand.builder().customerId(CUSTOMER).userName(ALICE)
                .firstName("Alice").lastName("Nguyen").phoneNumber(new PhoneNumber("+84901234567"))
                .email(new Email("alice@example.com")).build());
    }

    @Test
    void aRepeatOfAReadyAccountIs200() throws Exception {
        when(service.register(any())).thenReturn(new RegisterCustomerResult.Ready(REQUEST, CUSTOMER, ALICE, false));

        call(BODY).andExpect(status().isOk()).andExpect(jsonPath("$.data.state").value("READY"));
    }

    @Test
    void eachRefusalHasItsStatusAndCode() throws Exception {
        expect(new RegisterCustomerResult.IdentityConflict(), 409, "IDENTITY_CONFLICT");
        expect(new RegisterCustomerResult.ProfileIncomplete(), 409, "CUSTOMER_PROFILE_INCOMPLETE");
        expect(new RegisterCustomerResult.Unavailable(), 503, "ACCOUNT_CREATION_UNAVAILABLE");
    }

    @Test
    void invalidFieldsAre400WithFieldNamesButNoValues() throws Exception {
        String bad = BODY.replace("+84901234567", "0901234567").replace("\"alice\"", "\"a\"");

        call(bad, "en").andExpect(status().isBadRequest())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.error.message").value("The request was rejected"))
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
    void aValueThatPassesBeanValidationButNotTheValueObjectIs400() throws Exception {
        // "a@b" satisfies @Email but not the domain Email format.
        call(BODY.replace("alice@example.com", "a@b")).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$..value").doesNotExist());
        verifyNoInteractions(service);
    }

    @Test
    void withoutAcceptLanguageTheMessageIsVietnamese() throws Exception {
        when(service.register(any())).thenReturn(new RegisterCustomerResult.IdentityConflict());

        call(BODY).andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("IDENTITY_CONFLICT"))
                .andExpect(jsonPath("$.error.message").value(Matchers.startsWith("Khách hàng")));
        call(BODY.replace("+84901234567", "0901234567")).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value("Yêu cầu không hợp lệ"))
                .andExpect(jsonPath("$.error.details[0].message").value("Không đúng định dạng"));
    }

    @Test
    void anUnreadableBodyIs400() throws Exception {
        call("{not json").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("REQUEST_REJECTED"))
                .andExpect(jsonPath("$.error.details").isEmpty());
    }

    private void expect(RegisterCustomerResult result, int status, String code) throws Exception {
        when(service.register(any())).thenReturn(result);
        call(BODY).andExpect(status().is(status))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value(code))
                .andExpect(jsonPath("$.error.details").isEmpty());
    }

    private ResultActions call(String json) throws Exception {
        return mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions call(String json, String language) throws Exception {
        return mvc.perform(post(PATH).header("Accept-Language", language)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }
}
