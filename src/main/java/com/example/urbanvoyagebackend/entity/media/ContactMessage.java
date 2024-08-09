package com.example.urbanvoyagebackend.entity.media;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "contact_messages")
public class ContactMessage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String fullName;
    private String email;
    private String message;
    private LocalDateTime createdAt;

    // Getters and setters
    // ...
}