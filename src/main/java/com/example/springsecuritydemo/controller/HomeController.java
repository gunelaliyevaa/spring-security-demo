package com.example.springsecuritydemo.controller;


import com.example.springsecuritydemo.service.JwtService;
import io.jsonwebtoken.Header;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
@Slf4j
@RequestMapping("/api/v1/home")
@RequiredArgsConstructor
public class HomeController {

    private final JwtService jwtService;

    @GetMapping
    public String hello(@RequestHeader("Authorization") String authorizationHeader) {
        log.info("HEADER EXTRACTED: {}", extractToken(authorizationHeader));
        return "home";
    }

    private String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // Remove "Bearer " prefix
        }
        return null;
    }
}
