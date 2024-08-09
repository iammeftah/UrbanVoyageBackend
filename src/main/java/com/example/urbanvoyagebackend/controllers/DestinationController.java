package com.example.urbanvoyagebackend.controllers;


import com.example.urbanvoyagebackend.entity.media.Destination;
import com.example.urbanvoyagebackend.service.media.DestinationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/destinations")
public class DestinationController {
    @Autowired
    private DestinationService destinationService;

    @PostMapping
    public ResponseEntity<Destination> createDestination(@RequestParam("title") String title,
                                                         @RequestParam("description") String description,
                                                         @RequestParam("image") MultipartFile image) throws IOException {
        Destination destination = destinationService.createDestination(title, description, image);
        return ResponseEntity.ok(destination);
    }

    @GetMapping
    public ResponseEntity<List<Destination>> getAllDestinations() {
        List<Destination> destinations = destinationService.getAllDestinations();
        return ResponseEntity.ok(destinations);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Destination> getDestinationById(@PathVariable Long id) {
        Destination destination = destinationService.getDestinationById(id);
        return ResponseEntity.ok(destination);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Destination> updateDestination(@PathVariable Long id,
                                                         @RequestParam("title") String title,
                                                         @RequestParam("description") String description,
                                                         @RequestParam(value = "image", required = false) MultipartFile image) throws IOException {
        Destination destination = destinationService.updateDestination(id, title, description, image);
        return ResponseEntity.ok(destination);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteDestination(@PathVariable Long id) throws IOException {
        destinationService.deleteDestination(id);
        return ResponseEntity.noContent().build();
    }
}