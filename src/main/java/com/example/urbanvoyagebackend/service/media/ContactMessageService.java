package com.example.urbanvoyagebackend.service.media;

import com.example.urbanvoyagebackend.entity.media.ContactMessage;
import com.example.urbanvoyagebackend.repository.media.ContactMessageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ContactMessageService {
    @Autowired
    private ContactMessageRepository contactMessageRepository;

    public List<ContactMessage> getAllMessages() {
        return contactMessageRepository.findAll();
    }

    public void deleteMessage(Long id) {
        contactMessageRepository.deleteById(id);
    }
}