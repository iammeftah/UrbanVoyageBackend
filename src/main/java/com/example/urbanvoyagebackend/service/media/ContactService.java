package com.example.urbanvoyagebackend.service.media;

import com.example.urbanvoyagebackend.entity.media.Contact;
import com.example.urbanvoyagebackend.entity.media.ContactMessage;
import com.example.urbanvoyagebackend.entity.users.Role;
import com.example.urbanvoyagebackend.repository.media.ContactRepository;
import com.example.urbanvoyagebackend.repository.users.UserRepository;
import com.example.urbanvoyagebackend.service.users.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ContactService {
    @Autowired
    private ContactRepository contactRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private UserRepository userRepository;


    public List<Contact> getAllMessages() {
        return contactRepository.findAll();
    }

    public void deleteMessage(Long id) {
        contactRepository.deleteById(id);
    }

    public int getUnreadMessageCount() {
        return contactRepository.countByReadFalse();
    }

    public Contact markAsRead(Long id) {
        Contact contact = contactRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Contact not found"));
        contact.setRead(true);
        return contactRepository.save(contact);
    }


    public Contact saveContact(Contact contact) {
        contact.setCreatedAt(LocalDateTime.now());
        contact.setRead(false);
        Contact savedContact = contactRepository.save(contact);

        // Send email to all admin users
        sendContactNotificationEmail(savedContact);

        return savedContact;
    }


    private void sendContactNotificationEmail(Contact contact) {
        String subject = "New Contact Message from " + contact.getFullName();
        String messageContent = "From: " + contact.getFullName() + "\n"
                + "Email: " + contact.getEmail() + "\n\n"
                + "Message: " + contact.getMessage();

        List<String> adminEmails = userRepository.findEmailsByRole(Role.ROLE_ADMIN);

        for (String adminEmail : adminEmails) {
            emailService.sendContactNotificationEmail(adminEmail, subject, messageContent);
        }
    }

    private String createContactMessageContent(Contact contact) {
        return "<!DOCTYPE html>"
                + "<html lang='en'>"
                + "<head>"
                + "<meta charset='UTF-8'>"
                + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                + "<title>New Contact Message</title>"
                + "<style>"
                + "body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }"
                + ".container { max-width: 600px; margin: 0 auto; padding: 20px; }"
                + ".header { background-color: #06b6d4; color: white; padding: 20px; text-align: center; }"
                + ".content { background-color: #f9f9f9; padding: 20px; border-radius: 5px; }"
                + ".message { font-size: 16px; margin: 20px 0; padding: 10px; background-color: #e0e0e0; border-radius: 5px; }"
                + ".footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }"
                + "</style>"
                + "</head>"
                + "<body>"
                + "<div class='container'>"
                + "<div class='header'>"
                + "<h1>New Contact Message</h1>"
                + "</div>"
                + "<div class='content'>"
                + "<p>A new contact message has been received:</p>"
                + "<p><strong>From:</strong> " + contact.getFullName() + "</p>"
                + "<p><strong>Email:</strong> " + contact.getEmail() + "</p>"
                + "<div class='message'>" + contact.getMessage() + "</div>"
                + "</div>"
                + "<div class='footer'>"
                + "<p>&copy; 2024 UrbanVoyage. All rights reserved.</p>"
                + "</div>"
                + "</div>"
                + "</body>"
                + "</html>";
    }
}