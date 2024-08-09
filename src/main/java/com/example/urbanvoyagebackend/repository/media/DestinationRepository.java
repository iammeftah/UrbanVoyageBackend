package com.example.urbanvoyagebackend.repository.media;

import com.example.urbanvoyagebackend.entity.media.Destination;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DestinationRepository extends JpaRepository<Destination, Long> {
}