package com.example.springsecuritydemo.service;

import com.example.springsecuritydemo.dao.entity.User;
import com.example.springsecuritydemo.jwt.JwtAuthenticationRequest;
import com.example.springsecuritydemo.jwt.JwtAuthenticationResponse;
import com.example.springsecuritydemo.jwt.RegistrationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;

public interface AuthenticationService {
    JwtAuthenticationResponse register(RegistrationRequest request);

    JwtAuthenticationResponse login(JwtAuthenticationRequest request);

    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;

    /*
     * TODO: forgotPassword()
     * TODO: changePassword()
     *  TODO
     */

}
