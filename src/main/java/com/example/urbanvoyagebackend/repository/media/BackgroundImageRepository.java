package com.example.urbanvoyagebackend.repository.media;

import com.example.urbanvoyagebackend.entity.media.BackgroundImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BackgroundImageRepository extends JpaRepository<BackgroundImage, Long> {
    BackgroundImage findByActiveTrue();
    void deleteAll();
}