package com.example.urbanvoyagebackend.service.travel;

import com.example.urbanvoyagebackend.entity.travel.Sponsor;
import com.example.urbanvoyagebackend.exception.ResourceNotFoundException;
import com.example.urbanvoyagebackend.repository.travel.SponsorRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SponsorService {
    private final SponsorRepository sponsorRepository;

    @Autowired
    public SponsorService(SponsorRepository sponsorRepository) {
        this.sponsorRepository = sponsorRepository;
    }

    public List<Sponsor> getAllSponsors() {
        return sponsorRepository.findAll();
    }

    public Sponsor createSponsor(Sponsor sponsor) {
        return sponsorRepository.save(sponsor);
    }

    public Sponsor updateSponsor(Long id, Sponsor sponsorDetails) {
        Sponsor sponsor = sponsorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Sponsor not found with id: " + id));

        sponsor.setName(sponsorDetails.getName());
        sponsor.setImageUrl(sponsorDetails.getImageUrl());
        sponsor.setWebsite(sponsorDetails.getWebsite());

        return sponsorRepository.save(sponsor);
    }

    public void deleteSponsor(Long id) {
        Sponsor sponsor = sponsorRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Sponsor not found with id: " + id));

        sponsorRepository.delete(sponsor);
    }
}