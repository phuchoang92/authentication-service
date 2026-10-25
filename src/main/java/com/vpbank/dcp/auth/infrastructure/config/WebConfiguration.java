package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.infrastructure.adapter.in.web.ResponseHeadersFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration(proxyBeanMethods = false)
public class WebConfiguration {

    @Bean
    ResponseHeadersFilter responseHeadersFilter() {
        return new ResponseHeadersFilter();
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
