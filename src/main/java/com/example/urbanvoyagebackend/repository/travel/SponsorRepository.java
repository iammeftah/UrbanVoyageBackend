package com.example.urbanvoyagebackend.repository.travel;

import com.example.urbanvoyagebackend.entity.travel.Sponsor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SponsorRepository extends JpaRepository<Sponsor, Long> {
}