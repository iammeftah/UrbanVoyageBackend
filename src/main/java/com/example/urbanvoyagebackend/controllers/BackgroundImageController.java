package com.example.urbanvoyagebackend.controllers;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.example.urbanvoyagebackend.service.media.BackgroundImageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/background-image")
public class BackgroundImageController {

    @Autowired
    private Cloudinary cloudinary;

    @Autowired
    private BackgroundImageService backgroundImageService;

    @GetMapping
    public ResponseEntity<?> getBackgroundImage() {
        String imageUrl = backgroundImageService.getCurrentBackgroundImageUrl();
        return ResponseEntity.ok(Map.of("imageUrl", imageUrl != null ? imageUrl : ""));
    }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadBackgroundImage(@RequestParam("file") MultipartFile file) {
        try {
            Map uploadResult = cloudinary.uploader().upload(file.getBytes(), ObjectUtils.asMap("folder", "background_images"));
            String imageUrl = (String) uploadResult.get("url");

            backgroundImageService.saveNewBackgroundImage(imageUrl);

            return ResponseEntity.ok(Map.of("imageUrl", imageUrl));
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body("Failed to upload image");
        }
    }

    @PostMapping("/truncate")
    public ResponseEntity<?> truncateBackgroundImages() {
        try {
            backgroundImageService.truncateBackgroundImages();
            return ResponseEntity.ok(Map.of("message", "Background images truncated successfully"));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body("Failed to truncate background images");
        }
    }
}