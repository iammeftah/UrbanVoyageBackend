package com.example.urbanvoyagebackend.service.users;

import com.example.urbanvoyagebackend.dto.UserDTO;
import com.example.urbanvoyagebackend.entity.users.Client;
import com.example.urbanvoyagebackend.entity.users.Role;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.repository.users.UserRepository;
import com.example.urbanvoyagebackend.utils.MD5Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class UserService implements UserDetailsService {




    private final UserRepository userRepository;
    private final Map<String, UserDTO> unverifiedUsers = new HashMap<>();
    private final ConcurrentMap<String, OtpData> otpStorage = new ConcurrentHashMap<>();


    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User registerUser(UserDTO userDTO) {
        Client client = new Client();
        client.setFirstName(userDTO.getFirstName());
        client.setLastName(userDTO.getLastName());
        client.setPhoneNumber(userDTO.getPhoneNumber());
        client.setEmail(userDTO.getEmail());
        client.setUsername(userDTO.getUsername());

        // Hash password using MD5
        String hashedPassword = MD5Util.md5(userDTO.getPassword());
        client.setPassword(hashedPassword);

        if (client.getUsername() == null || client.getUsername().isEmpty()) {
            client.setUsername(generateUniqueUsername(userDTO.getFirstName(), userDTO.getLastName()));
        }

        return userRepository.save(client);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public boolean existsByPhoneNumber(String phoneNumber) {
        return userRepository.existsByPhoneNumber(phoneNumber);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public void updateUser(User user) {
        userRepository.save(user);
    }

    public void storeUnverifiedUser(UserDTO userDTO, String verificationCode) {
        userDTO.setVerificationCode(verificationCode);
        unverifiedUsers.put(userDTO.getEmail(), userDTO);
    }

    public UserDTO getUnverifiedUser(String email) {
        return unverifiedUsers.get(email);
    }

    public User registerVerifiedUser(UserDTO userDTO) {
        Client client = new Client();
        client.setFirstName(userDTO.getFirstName());
        client.setLastName(userDTO.getLastName());
        client.setPhoneNumber(userDTO.getPhoneNumber());
        client.setEmail(userDTO.getEmail());
        client.setUsername(userDTO.getUsername());
        client.setVerificationCode(userDTO.getVerificationCode());

        // Hash password using MD5
        String hashedPassword = MD5Util.md5(userDTO.getPassword());
        client.setPassword(hashedPassword);

        if (client.getUsername() == null || client.getUsername().isEmpty()) {
            client.setUsername(generateUniqueUsername(userDTO.getFirstName(), userDTO.getLastName()));
        }

        client.setVerified(true);

        User savedUser = userRepository.save(client);
        unverifiedUsers.remove(userDTO.getEmail());
        return savedUser;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isEmpty()) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }
        return new org.springframework.security.core.userdetails.User(
                user.get().getEmail(),
                user.get().getPassword(),
                user.get().isVerified(),
                true,
                true,
                true,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    // Method to generate a unique username if not provided
    private String generateUniqueUsername(String firstName, String lastName) {
        // Implement your logic to generate a unique username here
        return firstName.toLowerCase() + "." + lastName.toLowerCase();
    }

    public List<String> getAdminEmails() {
        return userRepository.findEmailsByRole(Role.ROLE_ADMIN);
    }


    public String getMaskedPhoneNumber(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isPresent()) {
            String phoneNumber = user.get().getPhoneNumber();
            // Mask all but the last 4 digits
            return phoneNumber.replaceAll("\\d(?=\\d{4})", "*");
        }
        return null;
    }

    public void storeOTP(String email, String otp) {
        otpStorage.put(email, new OtpData(otp, LocalDateTime.now()));
    }

    public boolean verifyOTP(String email, String otp) {
        OtpData storedOtpData = otpStorage.get(email);
        if (storedOtpData != null && storedOtpData.otp.equals(otp)) {
            // Check if OTP is not older than 5 minutes
            if (ChronoUnit.MINUTES.between(storedOtpData.creationTime, LocalDateTime.now()) <= 5) {
                otpStorage.remove(email);  // Remove OTP after successful verification
                return true;
            }
        }
        return false;
    }



    public void resetPassword(String email, String newPassword) {
        System.out.println("Attempting to reset password for email: " + email);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String hashedPassword = MD5Util.md5(newPassword);
        user.setPassword(hashedPassword);

        userRepository.save(user);
        System.out.println("Password reset successful for email: " + email);
    }

    private static class OtpData {
        String otp;
        LocalDateTime creationTime;

        OtpData(String otp, LocalDateTime creationTime) {
            this.otp = otp;
            this.creationTime = creationTime;
        }
    }



}
