package com.springsecurity.securitydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
// NOTE: Trigger role-based authorization
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated());
        // NOTE: No logout and login routes and form
        // http.formLogin(withDefaults());
        // NOTE: Create a stateless API
        http.sessionManagement(session -> session.sessionCreationPolicy
         (SessionCreationPolicy.STATELESS));
        http.httpBasic(withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
        // NOTE: Allow frames from same origin (This is necessary because the H2
        //  console runs inside an HTML frame, and Spring Security blocks frames  by
        //  default to prevent clickjacking attacks)
        http.headers(headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()));
        return http.build();
    }

    // NOTE: Create users and manage them in memory
    /*
    @Bean
    public UserDetailsService userDetailsService() {
        // NOTE: noop -> tells Spring to save password as plain text. Usually we should
        //  encode the password
        UserDetails user1 =
                User.withUsername("user1").password("{noop}12345").roles("USER").build();

        UserDetails admin =
                User.withUsername("admin").password("{noop}adminPass").roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user1, admin);
    }
    */
}
