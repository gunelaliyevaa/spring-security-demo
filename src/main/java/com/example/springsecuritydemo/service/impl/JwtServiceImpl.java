package com.example.springsecuritydemo.service.impl;

import com.example.springsecuritydemo.jwt.JwtAuthenticationRequest;
import com.example.springsecuritydemo.service.JwtService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;


    private final UserDetailsService userDetailsService;

    Set<String> blackListedTokens = new HashSet<>();


    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); //subject = username STRING
    }

    public UserDetails extractUserDetails(JwtAuthenticationRequest request) {
        String username = extractUsername(request.getUsername());
        return userDetailsService.loadUserByUsername(request.getUsername());
    }

    @Override
    public Claims extractAllClaims(String token) {  //claims are the part of jwt token that contain details about the user
        Claims claims = Jwts
                .parser()
                .verifyWith(getSignInKey()) //sign in key is used to create signature part of token and is used to verify the sender of jwt and ensure that message hasn't change along the way
                .build()
                .parseSignedClaims(token)
                .getPayload();

        log.info("Extracted Claims: " + claims);

        return claims;
    }


    @Override
    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims); //??
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .claims()
                .add(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration)) //valid for 24 hours 1000ms
                .and()
                .signWith(getSignInKey()) // JwtBuilder signWith(Key key) throws InvalidKeyException;
                .compact();
    }

    @Override
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        log.info("Access token exp: {}", jwtExpiration);
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        String accessToken = generateToken(new HashMap<>(), userDetails);
        log.info("Generated access token: {}", accessToken);
        return accessToken;
    }


    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        String refreshToken = buildToken(new HashMap<>(), userDetails, refreshExpiration);
        log.info("Refresh token exp: {}", refreshExpiration);
        log.info("Generated refresh token: {}", refreshToken);

        return refreshToken; //Why do we need to pass an empty hashmap instead of extraClaims?
    }

    @Override
    public Map<String, String> generateTokenPair(UserDetails userDetails) {
        String accessToken = generateToken(userDetails);
        String refreshToken = generateRefreshToken(userDetails);
        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
    }


    private SecretKey getSignInKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            // FOR DEBUGGING:
            log.info("Decoded secret key (first 8 bytes): {}", Arrays.copyOfRange(keyBytes, 0, 8));
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            log.error("Failed to decode secretKey. This is likely a configuration error.", e);
            throw new JwtException("Invalid JWT secret key configuration.");
        }
    }

    @Override
    public void invalidateToken(String token) {
        blackListedTokens.add(token);
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token) && !blackListedTokens.contains(token);
    }

    @Override
    public boolean isTokenExpired(String token) {
        Date exp = extractClaim(token, Claims::getExpiration);
        return exp.before(new Date());
    }

}