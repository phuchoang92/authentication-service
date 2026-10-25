package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;

/** The properties files are the error catalogue: every code in every language, nothing extra. */
class ErrorCatalogueTest {
    private static final Set<String> CODES = Arrays.stream(ErrorCodes.class.getDeclaredFields())
            .filter(f -> Modifier.isStatic(f.getModifiers()))
            .map(f -> {
                try {
                    return (String) f.get(null);
                } catch (IllegalAccessException e) {
                    throw new IllegalStateException(e);
                }
            }).collect(Collectors.toSet());

    @Test
    void everyLanguageFileHasExactlyTheErrorCodes() throws IOException {
        for (Locale locale : RestConfiguration.SUPPORTED_LOCALES) {
            assertThat(keys("messages/errors_" + locale.getLanguage() + ".properties"))
                    .as(locale.getLanguage()).containsExactlyInAnyOrderElementsOf(CODES);
        }
        assertThat(keys("ValidationMessages_vi.properties"))
                .containsExactlyInAnyOrderElementsOf(keys("ValidationMessages_en.properties"));
    }

    @Test
    void textFollowsTheRequestLocaleAndFallsBackToVietnamese() {
        ErrorMessages errors = new ErrorMessages(RestConfiguration.errorMessageSource());
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        assertThat(errors.message(ErrorCodes.IDENTITY_CONFLICT)).isEqualTo(
                "The customer or user name is linked to another identity");
        LocaleContextHolder.setLocale(RestConfiguration.DEFAULT_LOCALE);
        assertThat(errors.message(ErrorCodes.IDENTITY_CONFLICT)).startsWith("Khách hàng");
        LocaleContextHolder.resetLocaleContext();
    }

    private static Set<String> keys(String resource) throws IOException {
        Properties properties = new Properties();
        try (var in = new InputStreamReader(
                ErrorCatalogueTest.class.getClassLoader().getResourceAsStream(resource), StandardCharsets.UTF_8)) {
            properties.load(in);
        }
        return properties.stringPropertyNames();
    }
}
