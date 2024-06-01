package com.example.springsecuritydemo.service.impl;

import com.example.springsecuritydemo.dao.entity.Token;
import com.example.springsecuritydemo.dao.repo.TokenRepository;
import com.example.springsecuritydemo.dao.repo.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class LogoutServiceImpl implements LogoutHandler {

    private final TokenRepository tokenRepository;


    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        log.info("Logout Request Details: {}", request.getServletContext());

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {

            log.info("Logout without valid token detected. Redirecting to login page or returning a response indicating logout success.");

            return;
        }

        final String jwtToken = authHeader.substring(7).trim();
        log.info("Token extracted: {}", jwtToken);

        var storedToken = tokenRepository.findByToken(jwtToken).orElse(null);
        log.info("Token retrieved: {}", storedToken);

        if (storedToken != null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            log.info("Stored Token isExpired, isRevoked: {},{}", storedToken.isExpired(), storedToken.isRevoked());
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}
