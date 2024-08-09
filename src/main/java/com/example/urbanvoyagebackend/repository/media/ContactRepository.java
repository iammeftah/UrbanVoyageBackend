package com.example.urbanvoyagebackend.repository.media;



import com.example.urbanvoyagebackend.entity.media.Contact;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ContactRepository extends JpaRepository<Contact, Long> {
    int countByReadFalse();
}