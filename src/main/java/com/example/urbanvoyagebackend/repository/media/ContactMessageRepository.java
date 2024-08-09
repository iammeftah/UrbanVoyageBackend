package com.example.urbanvoyagebackend.repository.media;

import com.example.urbanvoyagebackend.entity.media.ContactMessage;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ContactMessageRepository extends JpaRepository<ContactMessage, Long> {
}