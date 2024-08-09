package com.example.urbanvoyagebackend.service.media;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.example.urbanvoyagebackend.entity.media.Destination;
import com.example.urbanvoyagebackend.repository.media.DestinationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import com.example.urbanvoyagebackend.exception.ResourceNotFoundException;

import java.io.IOException;
import java.util.List;
import java.util.Map;
@Service
public class DestinationService {
    @Autowired
    private DestinationRepository destinationRepository;

    @Autowired
    private Cloudinary cloudinary;

    public Destination createDestination(String title, String description, MultipartFile image) throws IOException {
        Map uploadResult = cloudinary.uploader().upload(image.getBytes(), ObjectUtils.emptyMap());
        String imageUrl = (String) uploadResult.get("url");

        Destination destination = new Destination();
        destination.setTitle(title);
        destination.setDescription(description);
        destination.setImageUrl(imageUrl);

        return destinationRepository.save(destination);
    }

    public List<Destination> getAllDestinations() {
        return destinationRepository.findAll();
    }

    public Destination getDestinationById(Long id) {
        return destinationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Destination not found with id: " + id));
    }

    public Destination updateDestination(Long id, String title, String description, MultipartFile image) throws IOException {
        Destination destination = getDestinationById(id);
        destination.setTitle(title);
        destination.setDescription(description);

        if (image != null && !image.isEmpty()) {
            Map uploadResult = cloudinary.uploader().upload(image.getBytes(), ObjectUtils.emptyMap());
            String imageUrl = (String) uploadResult.get("url");
            destination.setImageUrl(imageUrl);
        }

        return destinationRepository.save(destination);
    }

    public void deleteDestination(Long id) throws IOException {
        Destination destination = getDestinationById(id);
        if (destination.getImageUrl() != null) {
            String publicId = extractPublicIdFromUrl(destination.getImageUrl());
            cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
        }
        destinationRepository.deleteById(id);
    }

    private String extractPublicIdFromUrl(String imageUrl) {
        // Extract public ID from Cloudinary URL (implementation depends on your URL format)
        // This is a simplified example
        String[] parts = imageUrl.split("/");
        String fileName = parts[parts.length - 1];
        return fileName.substring(0, fileName.lastIndexOf('.'));
    }
}