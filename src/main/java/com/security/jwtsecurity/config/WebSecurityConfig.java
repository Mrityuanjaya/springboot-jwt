package com.security.jwtsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class WebSecurityConfig {
    // some of the original code was omitted for brevity

    private static final String[] WHITE_LIST_URLS = {
    };

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers(WHITE_LIST_URLS)
                .permitAll()
                .and()
                .authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**"))
                .permitAll();
        http.csrf().disable();
        http.headers().frameOptions().disable();

        return http.build();
    }
}
