package com.springsecurity.securitydemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {
    @GetMapping("/hello")
    public String sayHello() {
        return "Hello";
    }

    // Only user can view it
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello user";
    }

    // Only admin can view it
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello admin";
    }
}
