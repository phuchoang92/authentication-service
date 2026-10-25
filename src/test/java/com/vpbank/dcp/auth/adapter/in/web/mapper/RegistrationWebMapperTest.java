package com.vpbank.dcp.auth.adapter.in.web.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.adapter.in.web.common.ApiEnvelope;
import com.vpbank.dcp.auth.adapter.in.web.common.ErrorMessages;
import com.vpbank.dcp.auth.adapter.in.web.common.InvalidRequestException;
import com.vpbank.dcp.auth.adapter.in.web.dto.request.RegistrationRequest;
import com.vpbank.dcp.auth.adapter.in.web.dto.response.RegistrationResponse;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerCommand;
import com.vpbank.dcp.auth.application.port.in.RegisterCustomerResult;
import com.vpbank.dcp.auth.config.WebConfiguration;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class RegistrationWebMapperTest {
    private static final RegistrationId REQUEST =
            new RegistrationId(UUID.fromString("22222222-2222-4222-8222-222222222222"));
    private final RegistrationWebMapper mapper =
            new RegistrationWebMapper(new ErrorMessages(WebConfiguration.errorMessageSource()));

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void buildsValueObjectsAndTreatsABlankEmailAsAbsent() {
        RegisterCustomerCommand command = mapper.toCommand(
                new RegistrationRequest("90359", "alice", "Alice", "Nguyen", "+84901234567", " "));

        assertThat(command.customerId()).isEqualTo(new CustomerId("90359"));
        assertThat(command.userName()).isEqualTo(new UserName("alice"));
        assertThat(command.phoneNumber()).isEqualTo(new PhoneNumber("+84901234567"));
        assertThat(command.email()).isNull();
        assertThat(mapper.toCommand(new RegistrationRequest("90359", "alice", "Alice", "Nguyen",
                "+84901234567", "a@b.co")).email()).isEqualTo(new Email("a@b.co"));
    }

    @Test
    void aValueTheValueObjectRefusesIsAnInvalidRequest() {
        assertThatThrownBy(() -> mapper.toCommand(
                new RegistrationRequest("90359", "alice", "Alice", "Nguyen", "+84901234567", "a@b")))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessageContaining("Email");
    }

    @Test
    void readyIs201WhenCreatedAnd200WhenRepeated() {
        ResponseEntity<?> created = mapper.toResponse(
                new RegisterCustomerResult.Ready(REQUEST, new CustomerId("90359"), new UserName("alice"), true));
        ResponseEntity<?> repeated = mapper.toResponse(
                new RegisterCustomerResult.Ready(REQUEST, new CustomerId("90359"), new UserName("alice"), false));

        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(repeated.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(created.getBody()).isEqualTo(ApiEnvelope.success(
                new RegistrationResponse(REQUEST.value(), "90359", "alice", "READY")));
    }

    @Test
    void eachRefusalHasItsStatusCodeAndLocalizedMessage() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertFailure(new RegisterCustomerResult.IdentityConflict(), HttpStatus.CONFLICT, "IDENTITY_CONFLICT",
                "The customer or user name is linked to another identity");
        assertFailure(new RegisterCustomerResult.ProfileIncomplete(), HttpStatus.CONFLICT,
                "CUSTOMER_PROFILE_INCOMPLETE", "The customer profile does not allow account creation");
        assertFailure(new RegisterCustomerResult.Unavailable(), HttpStatus.SERVICE_UNAVAILABLE,
                "ACCOUNT_CREATION_UNAVAILABLE", "Authentication account creation could not be completed");

        LocaleContextHolder.setLocale(WebConfiguration.DEFAULT_LOCALE);
        assertFailure(new RegisterCustomerResult.Unavailable(), HttpStatus.SERVICE_UNAVAILABLE,
                "ACCOUNT_CREATION_UNAVAILABLE", "Không thể hoàn tất việc tạo tài khoản lúc này");
    }

    private void assertFailure(RegisterCustomerResult result, HttpStatus status, String code, String message) {
        ResponseEntity<?> response = mapper.toResponse(result);
        assertThat(response.getStatusCode()).isEqualTo(status);
        ApiEnvelope.Failure body = (ApiEnvelope.Failure) response.getBody();
        assertThat(body.error().code()).isEqualTo(code);
        assertThat(body.error().message()).isEqualTo(message);
    }
}
