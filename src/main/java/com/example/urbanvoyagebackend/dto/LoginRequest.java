package com.example.urbanvoyagebackend.dto;


import com.example.urbanvoyagebackend.entity.users.Role;

import java.util.Set;

public class LoginRequest {
    // Getters and setters
    private String email;
    private String password;
    private Set<Role> roles;
    private boolean rememberMe;


    public LoginRequest() {
    }

    public LoginRequest(String email, String password ) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}