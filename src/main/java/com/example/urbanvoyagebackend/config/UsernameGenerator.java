package com.example.urbanvoyagebackend.config;

import com.example.urbanvoyagebackend.repository.users.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UsernameGenerator {

    private static UserRepository userRepository;

    @Autowired
    public UsernameGenerator(UserRepository userRepository) {
        UsernameGenerator.userRepository = userRepository;
    }

    public static String generateUniqueUsername(String firstName, String lastName) {
        String baseUsername = generateBaseUsername(firstName, lastName);
        String username = baseUsername;
        int suffix = 1;

        while (userRepository.existsByUsername(username)) {
            username = baseUsername + suffix;
            suffix++;
        }

        return username;
    }

    private static String generateBaseUsername(String firstName, String lastName) {
        // Example of generating a base username (e.g., using lowercase and concatenating)
        return firstName.toLowerCase() + "_" + lastName.toLowerCase();
    }
}
