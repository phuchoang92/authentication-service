package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ResponseHeadersFilter;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

/** Web-wide pieces: response headers, the request locale and the localized error catalogue. */
@Configuration(proxyBeanMethods = false)
public class RestConfiguration {
    public static final Locale DEFAULT_LOCALE = Locale.forLanguageTag("vi");
    public static final List<Locale> SUPPORTED_LOCALES = List.of(DEFAULT_LOCALE, Locale.ENGLISH);

    @Bean
    ResponseHeadersFilter responseHeadersFilter() {
        return new ResponseHeadersFilter();
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /** Accept-Language decides the language; anything unsupported or missing is Vietnamese. */
    @Bean
    LocaleResolver localeResolver() {
        return acceptHeaderLocaleResolver();
    }

    /** Error texts and Bean Validation texts, by language. Replaces Boot's default MessageSource. */
    @Bean
    MessageSource messageSource() {
        return errorMessageSource();
    }

    @Bean
    ErrorMessages errorMessages(MessageSource messageSource) {
        return new ErrorMessages(messageSource);
    }

    public static AcceptHeaderLocaleResolver acceptHeaderLocaleResolver() {
        AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver();
        resolver.setSupportedLocales(SUPPORTED_LOCALES);
        resolver.setDefaultLocale(DEFAULT_LOCALE);
        return resolver;
    }

    public static ResourceBundleMessageSource errorMessageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasenames("messages/errors", "ValidationMessages");
        source.setDefaultEncoding(StandardCharsets.UTF_8.name());
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
