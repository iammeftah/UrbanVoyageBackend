package com.example.urbanvoyagebackend.service.users;


import com.example.urbanvoyagebackend.dto.LoginResponse;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.repository.users.UserRepository;
import com.example.urbanvoyagebackend.utils.MD5Util;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Optional;

@Service
public class AuthService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private Long jwtExpirationInMs;

    @Value("${jwt.rememberMe.expiration}")
    private Long rememberMeExpiration;



    @Autowired
    private UserRepository userRepository;

    public LoginResponse authenticate(String email, String password, boolean rememberMe) {
        System.out.println("AuthService: Attempting to authenticate user with email: " + email);
        Optional<User> user = userRepository.findByEmail(email);
        System.out.println("Client: " + user);
        System.out.println("Entered password: " + password);

        if (user.isPresent() && verifyPassword(MD5Util.md5(password), user.get().getPassword())) {
            System.out.println("Stored password: " + MD5Util.md5(password));

            System.out.println();
            System.out.println("AuthService: Verifying password returns :" + verifyPassword(password,  user.get().getPassword()));
            System.out.println("AuthService: Client authentication successful");
            return createLoginResponse(user.orElse(null), rememberMe);
        }
        System.out.println("AuthService: client authentication failed");
        return null;
    }

    private boolean verifyPassword(String inputPassword, String storedPassword) {
        // Implement your password verification logic here
        // Example: Compare hashed passwords
        return inputPassword.equals(storedPassword); // Example comparison, adjust as needed
    }

    private LoginResponse createLoginResponse(User user, boolean rememberMe) {
        String token = generateToken(user.getEmail(), rememberMe);
        System.out.println("Generating JWT token: " + token);

        return new LoginResponse(
                user.getUserID(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getPhoneNumber(),
                user.getUsername(),
                user.getRoles(),
                token
        );
    }

    private String generateToken(String email, boolean rememberMe) {
        Date now = new Date();
        Date expiryDate = rememberMe
                ? new Date(now.getTime() + rememberMeExpiration)
                : new Date(now.getTime() + jwtExpirationInMs);

        String token = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();

        System.out.println("Generated token: " + token);
        return token;
    }

    private Key getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Optional<User> getCurrentUser(String email) {
        return userRepository.findByEmail(email);
    }

}
