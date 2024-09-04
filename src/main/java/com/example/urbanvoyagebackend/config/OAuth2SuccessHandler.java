package com.example.urbanvoyagebackend.config;

import com.example.urbanvoyagebackend.entity.users.Client;
import com.example.urbanvoyagebackend.entity.users.Role;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.repository.users.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> createNewUser(oAuth2User));

        // Generate JWT token
        String token = jwtTokenProvider.generateToken(user);

        // Redirect to frontend with token
        getRedirectStrategy().sendRedirect(request, response, "http://localhost:4200/oauth2/redirect?token=" + token);
    }

    private User createNewUser(OAuth2User oAuth2User) {
        Client newUser = new Client();
        newUser.setEmail(oAuth2User.getAttribute("email"));
        newUser.setFirstName(oAuth2User.getAttribute("given_name"));
        newUser.setLastName(oAuth2User.getAttribute("family_name"));
        newUser.setUsername(oAuth2User.getAttribute("email"));
        newUser.setPassword(generateRandomPassword());
        newUser.setVerified(true);
        newUser.addRole(Role.ROLE_CLIENT);
        newUser.setPhoneNumber("Not provided"); // Set a default value

        return userRepository.save(newUser);
    }

    private String generateRandomPassword() {
        // Implement a method to generate a random, secure password
        return ""; // This is just a placeholder, use a proper random password generator
    }
}