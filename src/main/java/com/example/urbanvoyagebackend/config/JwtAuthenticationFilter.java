package com.example.urbanvoyagebackend.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = Logger.getLogger(JwtAuthenticationFilter.class.getName());

    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key signingKey;

    @PostConstruct
    public void init() {
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            throw new IllegalStateException("JWT secret is not set. Check your application properties.");
        }
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        logger.info("JwtAuthenticationFilter: Processing request to " + path);

        if (isPublicEndpoint(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractToken(request);
        logger.info("Extracted token: " + (token != null ? "present" : "null"));

        if (token == null) {
            logger.warning("No valid JWT token found in request headers for protected endpoint: " + path);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (validateToken(token)) {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                logger.info("Username from token: " + username);
                logger.info("Role from token: " + (role != null ? role : "null"));

                List<GrantedAuthority> authorities;
                if (role != null && !role.isEmpty()) {
                    authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                } else {
                    logger.warning("No role found in token. Assigning default role.");
                    authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
                }

                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(auth);
                logger.info("Authentication set in SecurityContext");
            }
        } catch (JwtException e) {
            logger.warning("Invalid JWT token: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/api/auth/") || path.startsWith("/error") || path.startsWith("/oauth2/")
                || path.startsWith("/api/routes/") || path.startsWith("/api/reservations/")
                || path.startsWith("/api/users/") || path.startsWith("/api/schedules/")
                || path.startsWith("/api/payment/") || path.startsWith("/api/passengers/")
                || path.startsWith("/api/translate/") || path.startsWith("/api/contact-messages/")
                || path.startsWith("/api/contacts/") || path.startsWith("/api/destinations/")
                || path.startsWith("/api/background-image/") || path.startsWith("/api/reset-password/")
                || path.startsWith("/api/faqs/");
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(token);
            logger.info("Token is valid");
            return true;
        } catch (JwtException e) {
            logger.warning("Invalid JWT token: " + e.getMessage());
            return false;
        }
    }
}