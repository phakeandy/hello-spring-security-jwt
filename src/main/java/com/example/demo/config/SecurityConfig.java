package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(
            authz ->
                authz
                    .requestMatchers(HttpMethod.GET, "/messages")
                    .access(OAuth2AuthorizationManagers.hasScope("message:read"))
                    .requestMatchers(HttpMethod.POST, "/messages")
                    .access(OAuth2AuthorizationManagers.hasScope("message:write"))
                    .anyRequest()
                    .permitAll())
        .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> {}))
        .csrf(csrf -> csrf.disable())
        .build();
  }
}
