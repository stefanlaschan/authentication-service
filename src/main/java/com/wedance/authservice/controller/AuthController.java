package com.wedance.authservice.controller;

import com.wedance.authservice.dto.AuthResponse;
import com.wedance.authservice.dto.LoginRequest;
import com.wedance.authservice.dto.SignupRequest;
import com.wedance.authservice.service.KeycloakService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final KeycloakService kc;

    public AuthController(KeycloakService kc) { this.kc = kc; }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody SignupRequest req) {
        kc.signup(req);
        return ResponseEntity.status(201).build();
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req) {
        AuthResponse token = kc.login(req);
        return ResponseEntity.ok(token);
    }
}