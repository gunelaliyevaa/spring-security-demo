package com.example.springsecuritydemo.controller;

import com.example.springsecuritydemo.jwt.JwtAuthenticationRequest;
import com.example.springsecuritydemo.jwt.JwtAuthenticationResponse;
import com.example.springsecuritydemo.jwt.RegistrationRequest;
import com.example.springsecuritydemo.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<JwtAuthenticationResponse> register(@RequestBody RegistrationRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> login(@RequestBody JwtAuthenticationRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public void refresh(HttpServletRequest request, //Request authorization header holds the refresh token
                        HttpServletResponse response) throws IOException {
        authService.refreshToken(request, response);
    }
}

