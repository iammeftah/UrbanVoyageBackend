package com.example.urbanvoyagebackend.entity.users;

import jakarta.persistence.*;

@Entity
@Table(name = "admins")
public class Admin extends User {

    public Admin() {
        super();
        this.addRole(Role.ROLE_ADMIN);
    }

    public Admin(String firstName, String lastName, String phoneNumber, String email, String username, String password) {
        super(firstName, lastName, phoneNumber, email, username, password);
        this.addRole(Role.ROLE_ADMIN);
    }

    // Admin-specific methods
    public void manageRoutes() {
        // Implementation for managing routes
    }

    public void manageSchedules() {
        // Implementation for managing schedules
    }

    public void viewStatistics() {
        // Implementation for viewing statistics
    }
}