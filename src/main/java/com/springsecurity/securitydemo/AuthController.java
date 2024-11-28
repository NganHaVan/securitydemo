package com.springsecurity.securitydemo;

import com.springsecurity.securitydemo.dto.LoginRequest;
import com.springsecurity.securitydemo.dto.LoginResponse;
import com.springsecurity.securitydemo.jwt.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest ) {
        Authentication authentication;
        try {
            authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException e) {
            Map<String, Object> mapper = new HashMap<>();
            mapper.put("message", "Bad credentials");
            mapper.put("status", false);
            return new ResponseEntity<Object>(mapper, HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles =
                userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

        LoginResponse response = new LoginResponse(jwtToken, userDetails.getUsername(), roles);
        return ResponseEntity.ok(response);
    }
}
