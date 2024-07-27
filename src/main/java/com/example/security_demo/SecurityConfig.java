package com.example.security_demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                requests
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated());
        http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        //http.formLogin(withDefaults());

        //For httpBasic
        // base64 encoded  user:password
        // Authorization header looks like:
        // Authorization: Basic YWRtaW46dGVzdDEyMw==
        //where YWRtaW46dGVzdDEyMw== is username:password encoded into base64
        //can use basic auth in the authorization tab of postman to attach the authorization header
        http.httpBasic(withDefaults());
        http.headers(headers->
                headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
        http.csrf(csrf->csrf.disable());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1= User.withUsername("user1")
                .password("{noop}test123") //{noop} prefix tells spring password should be saved as plain text
                .roles("USER")
                .build();
        UserDetails admin= User.withUsername("admin")
                .password("{noop}admin") //{noop} prefix tells spring password should be saved as plain text
                .roles("ADMIN")
                .build();

        //In-memory authentication
        return new InMemoryUserDetailsManager(user1,admin);
    }
}
