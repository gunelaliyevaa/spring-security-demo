package com.example.springsecuritydemo.service;

import jakarta.mail.MessagingException;

public interface PasswordService {
    void sendOtpEmail(String email, String otp) throws MessagingException;

    String generateOtp();

    String regenerateOtp(String email);

    String forgotPassword(String email) throws MessagingException;

    void sendPasswordResetEmail(String email) throws MessagingException;

    String resetPassword(String email, String newPassword);
}
