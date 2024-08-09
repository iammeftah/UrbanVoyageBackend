package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.models.EmailCheckRequest;
import com.example.urbanvoyagebackend.models.EmailRequest;
import com.example.urbanvoyagebackend.models.OTPVerificationRequest;
import com.example.urbanvoyagebackend.service.media.EmailService;
import com.example.urbanvoyagebackend.service.users.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.urbanvoyagebackend.models.ResetPasswordRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/api/reset-password")
public class ResetPasswordController {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @PostMapping("/check-email")
    public ResponseEntity<?> checkEmail(@RequestBody EmailCheckRequest request) {
        String email = request.getEmail();
        // Assuming UserService has a method to find user by email and get masked phone number
        String maskedPhoneNumber = userService.getMaskedPhoneNumber(email);

        if (maskedPhoneNumber != null) {
            Map<String, String> response = new HashMap<>();
            response.put("email", email);
            response.put("maskedPhoneNumber", maskedPhoneNumber);
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body("Email not found");
        }
    }

    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOTP(@RequestBody EmailRequest request) {
        String email = request.getEmail();
        String otp = generateOTP();

        userService.storeOTP(email, otp);
        emailService.sendOTPEmail(email, otp);

        return ResponseEntity.ok("OTP sent successfully");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOTP(@RequestBody OTPVerificationRequest request) {
        String email = request.getEmail();
        String otp = request.getOtp();

        boolean isValid = userService.verifyOTP(email, otp);

        if (isValid) {
            return ResponseEntity.ok("OTP verified successfully");
        } else {
            return ResponseEntity.badRequest().body("Invalid OTP");
        }
    }

    @PostMapping
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        System.out.println("Received reset password request for email: " + request.getEmail());
        try {
            userService.resetPassword(request.getEmail(), request.getNewPassword());
            System.out.println("Password reset successful for email: " + request.getEmail());
            return ResponseEntity.ok("Password reset successfully");
        } catch (Exception e) {
            System.err.println("Failed to reset password: " + e.getMessage());
            return ResponseEntity.badRequest().body("Failed to reset password: " + e.getMessage());
        }
    }

    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }




}