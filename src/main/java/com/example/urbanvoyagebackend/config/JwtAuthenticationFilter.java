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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = Logger.getLogger(JwtAuthenticationFilter.class.getName());

    @Value("${jwt.secret}")
    private String jwtSecret;

    public JwtAuthenticationFilter(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/oauth2") || request.getRequestURI().startsWith("/login/oauth2")) {
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println("JwtAuthenticationFilter: Processing request to " + request.getRequestURI());


        String token = extractToken(request);
        logger.info("Extracted token: " + (token != null ? "present" : "null"));

        if (token != null && validateToken(token)) {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            logger.info("Username from token: " + username);
            logger.info("token: " + token);

            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));



            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(auth);
            logger.info("Authentication set in SecurityContext");
        } else {
            logger.warning("No valid JWT token found in request headers");
        }

        filterChain.doFilter(request, response);
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
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            logger.info("Token is valid");
            return true;
        } catch (ExpiredJwtException e) {
            logger.warning("Token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.warning("Unsupported JWT token: " + e.getMessage());
        } catch (MalformedJwtException e) {
            logger.warning("Malformed JWT token: " + e.getMessage());
        } catch (SignatureException e) {
            logger.warning("Invalid JWT signature: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.warning("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }

    private Key getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
