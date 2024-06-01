package com.example.springsecuritydemo.service;

import com.example.springsecuritydemo.jwt.JwtAuthenticationRequest;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;


public interface JwtService {
    String extractUsername(String token);

    Claims extractAllClaims(String token);

    <T> T extractClaim(String token, Function<Claims, T> claimResolver);

    UserDetails extractUserDetails(JwtAuthenticationRequest request);

    String generateToken(
            Map<String, Object> extraClaims, //take string return object. when I want to store any extra info
            UserDetails userDetails
    );

    String generateToken(
            UserDetails userDetails
    );

    String generateRefreshToken(UserDetails userDetails);

    Map<String, String> generateTokenPair(UserDetails userDetails);

    void invalidateToken(String token);

    boolean isTokenExpired(String token);

    boolean isTokenValid(String token, UserDetails userDetails);
    //void invalidateToken(String token);

}
