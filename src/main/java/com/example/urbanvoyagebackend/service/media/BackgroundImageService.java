package com.example.urbanvoyagebackend.service.media;

import com.example.urbanvoyagebackend.entity.media.BackgroundImage;
import com.example.urbanvoyagebackend.repository.media.BackgroundImageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class BackgroundImageService {

    @Autowired
    private BackgroundImageRepository backgroundImageRepository;

    public String getCurrentBackgroundImageUrl() {
        BackgroundImage activeImage = backgroundImageRepository.findByActiveTrue();
        return activeImage != null ? activeImage.getImageUrl() : null;
    }

    @Transactional
    public void saveNewBackgroundImage(String imageUrl) {
        // Deactivate current active image
        BackgroundImage currentActive = backgroundImageRepository.findByActiveTrue();
        if (currentActive != null) {
            currentActive.setActive(false);
            backgroundImageRepository.save(currentActive);
        }

        // Save new active image
        BackgroundImage newImage = new BackgroundImage(imageUrl, true);
        backgroundImageRepository.save(newImage);
    }

    public void truncateBackgroundImages() {
        backgroundImageRepository.deleteAll();
        // Implement the logic to truncate the table
        // This might involve calling a repository method or using JdbcTemplate
        // For example:
        // backgroundImageRepository.truncate();
    }
}