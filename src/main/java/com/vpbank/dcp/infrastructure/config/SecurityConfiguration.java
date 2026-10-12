package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.port.out.security.DpopProofDecoder;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.DpopProofFilter;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.SecureWorkloadAuthorizationManager;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.SecurityErrorResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.security.WorkloadUriPrincipalExtractor;
import com.vpbank.dcp.infrastructure.config.properties.IngressProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityConfiguration {
    @Bean
    UserDetailsService workloadUsers() {
        return name -> User.withUsername(name).password("").authorities("WORKLOAD").build();
    }

    @Bean
    SecurityFilterChain authenticationSecurity(HttpSecurity http, IngressProperties ingress,
                                               DpopProofDecoder decoder, ExternalUriPolicy externalUris, Clock clock, JsonMapper json,
                                               UserDetailsService workloadUsers) throws Exception {
        var errors = new SecurityErrorResponse(json);
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .x509(x509 -> x509.x509PrincipalExtractor(
                                new WorkloadUriPrincipalExtractor(ingress.allowedWorkloadUris()))
                        .userDetailsService(workloadUsers))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(errors)
                        .accessDeniedHandler(errors))
                .authorizeHttpRequests(requests -> requests.anyRequest()
                        .access(new SecureWorkloadAuthorizationManager()))
                .addFilterAfter(new DpopProofFilter(decoder, externalUris, clock, errors), AuthorizationFilter.class)
                .build();
    }
}
