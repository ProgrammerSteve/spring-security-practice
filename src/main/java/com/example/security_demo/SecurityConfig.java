package com.example.security_demo;

import com.example.security_demo.jwt.AuthEntryPointJwt;
import com.example.security_demo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final DataSource dataSource;
    private final AuthEntryPointJwt unauthorizedHandler;

    public SecurityConfig(DataSource dataSource, AuthEntryPointJwt authEntryPointJwt) {
        this.dataSource = dataSource;
        this.unauthorizedHandler = authEntryPointJwt;
    }

//    @Bean
//    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((requests) ->
//                requests
//                        .requestMatchers("/h2-console/**").permitAll()
//                        .anyRequest().authenticated());
//        http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        //http.formLogin(withDefaults());
//
//        //For httpBasic
//        // base64 encoded  user:password
//        // Authorization header looks like:
//        // Authorization: Basic YWRtaW46dGVzdDEyMw==
//        //where YWRtaW46dGVzdDEyMw== is username:password encoded into base64
//        //can use basic auth in the authorization tab of postman to attach the authorization header
//        http.httpBasic(withDefaults());
//        http.headers(headers->
//                headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
//        http.csrf(csrf->csrf.disable());
//        return http.build();
//    }


    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
             //we want to permit all endpoints that goes into h2-console
            .requestMatchers("/h2-console/**").permitAll()
             //we want to permit endpoint for login
            .requestMatchers("/signin").permitAll()
             //all other requests are authenticated
            .anyRequest().authenticated())
             //session will be stateless for REST apis where no session states are maintained
             //in between requests.
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // adding exception handling mechanism
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));

        //done for h2 console
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        //done for h2 console
        http.csrf(AbstractHttpConfigurer::disable);

        //add authTokenFilter into the filter chain before UsernamePasswordAuthenticationFilter
        //if it is never added, it never gets executed
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        //returns the filter chain
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1= User.withUsername("user1")
                .password(passwordEncoder().encode("test123")) //{noop} prefix tells spring password should be saved as plain text
                .roles("USER")
                .build();
        UserDetails admin= User.withUsername("admin")
                .password(passwordEncoder().encode("test123")) //{noop} prefix tells spring password should be saved as plain text
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;

        //In-memory authentication
        //return new InMemoryUserDetailsManager(user1,admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
