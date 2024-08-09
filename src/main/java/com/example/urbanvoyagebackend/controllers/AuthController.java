package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.dto.LoginRequest;
import com.example.urbanvoyagebackend.dto.LoginResponse;
import com.example.urbanvoyagebackend.dto.UserDTO;
import com.example.urbanvoyagebackend.dto.VerificationRequest;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.service.media.EmailService;
import com.example.urbanvoyagebackend.service.users.AuthService;
import com.example.urbanvoyagebackend.service.users.UserService;
import com.example.urbanvoyagebackend.utils.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private Long jwtExpirationInMs;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthService authService;

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final EmailService emailService;

    public AuthController(AuthenticationManager authenticationManager,
                          UserService userService,
                          EmailService emailService) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.emailService = emailService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {
        if (userService.existsByUsername(userDTO.getUsername())) {
            return ResponseEntity.badRequest().body(createResponse("Error", "Username is already taken!"));
        }

        if (userService.existsByEmail(userDTO.getEmail())) {
            return ResponseEntity.badRequest().body(createResponse("Error", "Email is already in use!"));
        }

        String verificationCode = generateVerificationCode();
        System.out.println("Generated verification code: " + verificationCode); // Console output

        // Send verification email
        try {
            emailService.sendEmail(userDTO.getEmail(), verificationCode);
            System.out.println("Verification email sent to: " + userDTO.getEmail()); // Console output
        } catch (Exception e) {
            System.err.println("Failed to send verification email: " + e.getMessage());
            e.printStackTrace(); // This will print the full stack trace for debugging
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createResponse("Error", "Failed to send verification email: " + e.getMessage()));
        }

        // Store the unverified user details temporarily (you might want to use a cache or temporary storage)
        userService.storeUnverifiedUser(userDTO, verificationCode);

        return ResponseEntity.ok(createResponse("Success", "Verification code sent. Please check your email and verify your account."));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyEmail(@RequestBody VerificationRequest verificationRequest) {
        UserDTO unverifiedUser = userService.getUnverifiedUser(verificationRequest.getEmail());
        if (unverifiedUser == null) {
            return ResponseEntity.badRequest().body(createResponse("Error", "No pending verification for this email!"));
        }

        if (unverifiedUser.getVerificationCode().equals(verificationRequest.getVerificationCode())) {
            // Register the user in the database
            User user = userService.registerVerifiedUser(unverifiedUser);
            return ResponseEntity.ok(createResponse("Success", "Email verified successfully! Your account is now active."));
        } else {
            return ResponseEntity.badRequest().body(createResponse("Error", "Invalid verification code!"));
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        System.out.println("Controller: Received signin request for email: " + loginRequest.getEmail());
        System.out.println("Controller: Received signin request for password: " + loginRequest.getPassword());
        System.out.println("Controller: Remember Me: " + loginRequest.isRememberMe());

        try {
            LoginResponse response = authService.authenticate(loginRequest.getEmail(), loginRequest.getPassword(), loginRequest.isRememberMe());
            if (response != null) {
                System.out.println("Controller: Login successful for user: " + loginRequest.getEmail());
                System.out.println("Controller: Is user admin: " + response.getRoles());
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(response);
            } else {
                System.out.println("Controller: Login failed: Invalid credentials for user: " + loginRequest.getEmail());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"message\": \"Invalid email or password\"}");
            }
        } catch (Exception e) {
            System.out.println("Controller: Exception occurred during signin: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"message\": \"An error occurred: " + e.getMessage() + "\"}");
        }
    }


    @PostMapping("/check-user")
    public ResponseEntity<?> checkUserExists(@RequestBody Map<String, String> credentials) {
        String email = credentials.get("email");
        String phoneNumber = credentials.get("phoneNumber");

        boolean emailExists = userService.existsByEmail(email);
        boolean phoneExists = userService.existsByPhoneNumber(phoneNumber);

        Map<String, Boolean> response = new HashMap<>();
        response.put("emailExists", emailExists);
        response.put("phoneExists", phoneExists);

        return ResponseEntity.ok(response);
    }





    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(createResponse("Success", "User signed out successfully!"));
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }

    private Map<String, String> createResponse(String status, String message) {
        Map<String, String> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        return response;
    }

    @GetMapping("/user-details")
    public ResponseEntity<UserDTO> getUserDetails(@RequestParam String email) {
        Optional<User> user = userService.findByEmail(email);
        if (user.isEmpty()) {
            System.out.println("AuthController: User not found");
            return ResponseEntity.notFound().build();
        }
        System.out.println("AuthController: User found - " + user.get().getEmail());
        UserDTO userDTO = new UserDTO(user.get().getUserID(), user.get().getEmail(), user.get().getFirstName(), user.get().getLastName());
        return ResponseEntity.ok(userDTO);
    }
}
