package com.example.springsecuritydemo.service.impl;

import com.example.springsecuritydemo.dao.entity.Token;
import com.example.springsecuritydemo.dao.repo.TokenRepository;
import com.example.springsecuritydemo.enums.TokenType;
import com.example.springsecuritydemo.exception.UserAlreadyExistsException;
import com.example.springsecuritydemo.jwt.JwtAuthenticationRequest;
import com.example.springsecuritydemo.jwt.JwtAuthenticationResponse;
import com.example.springsecuritydemo.jwt.RegistrationRequest;

import com.example.springsecuritydemo.dao.entity.User;
import com.example.springsecuritydemo.dao.repo.UserRepository;
import com.example.springsecuritydemo.service.AuthenticationService;
import com.example.springsecuritydemo.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository repository;

    private final PasswordEncoder encoder;

    private final JwtService jwtService;

    private final AuthenticationManager authManager;

    private final TokenRepository tokenRepository;


    @Override
    public JwtAuthenticationResponse register(RegistrationRequest request) {
        //Register the user to repository and generate a token
        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(encoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        if (repository.existsByUsername(user.getUsername())) {
            throw new UserAlreadyExistsException("User with this username already exists");
        }

        if (repository.existsByEmail(user.getEmail())) {
            throw new UserAlreadyExistsException("User with this email already exists");
        }


        var savedUser = repository.save(user);
        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        saveToken(savedUser, accessToken);

        boolean equalTo = accessToken.equals(refreshToken);
        log.info("🔸TOKENS GENERATED ARE EQUAL: {}", equalTo);
        log.info("Authenticated User: {}", savedUser);


        saveToken(user, accessToken);
        saveToken(user, refreshToken);


        return JwtAuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken
                .build();
    }

    @Override
    public JwtAuthenticationResponse login(JwtAuthenticationRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        log.info("User authenticated - authService.login: {}", request.getUsername());
        var user = repository.findByUsername(request.getUsername()).orElseThrow();

        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        revokeAllTokens(user);

        boolean equalTo = accessToken.equals(refreshToken);
        log.info("🔸TOKENS GENERATED ARE EQUAL: {}", equalTo);

        saveToken(user, accessToken);
        saveToken(user, refreshToken);

        return JwtAuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        final String refreshToken;
        final String username;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        refreshToken = authHeader.substring(7).trim();
        username = jwtService.extractUsername(refreshToken);


        if (username != null) {
            var userDetails = this.repository.findByUsername(username).orElseThrow();

            if (jwtService.isTokenValid(refreshToken, userDetails)) {
                var accessToken = jwtService.generateToken(userDetails);
                var authResponse = JwtAuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private void saveToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .isExpired(false)
                .isRevoked(false)
                .build();
        tokenRepository.save(token);
    }


    private void revokeAllTokens(User user) {
        var validTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validTokens.isEmpty()) {
            return;
        }
        validTokens.forEach(token -> {
            token.setRevoked(true);
            token.setExpired(true);
        });
        tokenRepository.saveAll(validTokens);
    }
}

