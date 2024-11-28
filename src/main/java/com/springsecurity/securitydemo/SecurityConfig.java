package com.springsecurity.securitydemo;

import com.springsecurity.securitydemo.jwt.AuthEntryPointJwt;
import com.springsecurity.securitydemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
// NOTE: Trigger role-based authorization
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticateJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/signin").permitAll()
                .requestMatchers("/h2-console/**").hasRole("ADMIN")
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
        http.addFilterBefore(authenticateJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
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

    // NOTE: Allow db users to access -> JDBCUserDetailManager
//    @Bean
//    public UserDetailsService userDetailsService(){
//        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//        UserDetails user1 =
//                User.withUsername("user1").password(passwordEncoder().encode("12345")).roles("USER").build();
//
//        UserDetails admin =
//                User.withUsername("admin").password(passwordEncoder().encode("adminPass")).roles("ADMIN").build();
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);
//        return  userDetailsManager;
//    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return  new JdbcUserDetailsManager(dataSource);
    }

    @Bean
//    NOTE: CommandLineRunner is an interface used to execute code after the Spring application context is initialized.
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager userDetailsManager = (JdbcUserDetailsManager) userDetailsService(dataSource);
            UserDetails user1 =
                    User.withUsername("user1").password(passwordEncoder().encode("12345")).roles("USER").build();

            UserDetails admin =
                    User.withUsername("admin").password(passwordEncoder().encode("adminPass")).roles("ADMIN").build();
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
