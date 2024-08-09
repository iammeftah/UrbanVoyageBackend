package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.entity.travel.Sponsor;
import com.example.urbanvoyagebackend.service.travel.SponsorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/sponsors")
public class SponsorController {
    private final SponsorService sponsorService;

    @Autowired
    public SponsorController(SponsorService sponsorService) {
        this.sponsorService = sponsorService;
    }

    @GetMapping
    public List<Sponsor> getAllSponsors() {
        return sponsorService.getAllSponsors();
    }

    @PostMapping
    public ResponseEntity<Sponsor> createSponsor(@RequestBody Sponsor sponsor) {
        Sponsor newSponsor = sponsorService.createSponsor(sponsor);
        return new ResponseEntity<>(newSponsor, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Sponsor> updateSponsor(@PathVariable Long id, @RequestBody Sponsor sponsorDetails) {
        Sponsor updatedSponsor = sponsorService.updateSponsor(id, sponsorDetails);
        return ResponseEntity.ok(updatedSponsor);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteSponsor(@PathVariable Long id) {
        sponsorService.deleteSponsor(id);
        return ResponseEntity.ok().build();
    }
}