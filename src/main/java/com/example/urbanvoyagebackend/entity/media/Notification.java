package com.example.urbanvoyagebackend.entity.media;


import com.example.urbanvoyagebackend.entity.users.User;
import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "notifications")
public class Notification {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long notificationID;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String message;

    @Column(nullable = false)
    private Date sentDate;

    // Constructors, getters, and setters

    public Notification() {}

    public Notification(User user, String message, Date sentDate) {
        this.user = user;
        this.message = message;
        this.sentDate = sentDate;
    }

    // Getters and setters for all fields

    public boolean sendNotification() {
        // Implement notification sending logic
        return true;
    }
}