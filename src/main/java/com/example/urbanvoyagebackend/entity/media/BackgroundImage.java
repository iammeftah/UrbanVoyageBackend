package com.example.urbanvoyagebackend.entity.media;

import jakarta.persistence.*;

@Entity
@Table(name = "background_images")
public class BackgroundImage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String imageUrl;

    @Column(nullable = false)
    private boolean active;

    // Constructors, getters, and setters

    public BackgroundImage() {}

    public BackgroundImage(String imageUrl, boolean active) {
        this.imageUrl = imageUrl;
        this.active = active;
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}