package com.example.urbanvoyagebackend.controllers;


import com.example.urbanvoyagebackend.entity.media.Contact;
import com.example.urbanvoyagebackend.entity.media.ContactMessage;
import com.example.urbanvoyagebackend.service.media.ContactService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/contacts")
@CrossOrigin(origins = "http://localhost:4200")
public class ContactController {
    @Autowired
    private ContactService contactService;

    @PostMapping
    public ResponseEntity<Contact> createContact(@RequestBody Contact contact) {
        Contact savedContact = contactService.saveContact(contact);
        return ResponseEntity.ok(savedContact);
    }

    @GetMapping
    public ResponseEntity<List<Contact>> getAllMessages() {
        return ResponseEntity.ok(contactService.getAllMessages());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMessage(@PathVariable Long id) {
        contactService.deleteMessage(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/unread-count")
    public ResponseEntity<Integer> getUnreadMessageCount() {
        return ResponseEntity.ok(contactService.getUnreadMessageCount());
    }

    @PutMapping("/{id}/mark-as-read")
    public ResponseEntity<Contact> markAsRead(@PathVariable Long id) {
        Contact updatedContact = contactService.markAsRead(id);
        return ResponseEntity.ok(updatedContact);
    }
}