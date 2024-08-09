package com.example.urbanvoyagebackend.service.media;

import com.example.urbanvoyagebackend.dto.UserDTO;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Properties;
import java.util.Random;

@Service
public class EmailService {

    @Value("${spring.mail.host}")
    private String host;

    @Value("${spring.mail.port}")
    private int port;

    @Value("${spring.mail.username}")
    private String username;

    @Value("${spring.mail.password}")
    private String password;

    public void sendEmail(String to, String verificationCode) {
        try {
            JavaMailSender mailSender = getJavaMailSender();
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlMsg = createHtmlEmailContent(verificationCode);

            helper.setText(htmlMsg, true); // Use this to send an HTML email
            helper.setTo(to);
            helper.setSubject("UrbanVoyage Email Verification");
            helper.setFrom("noreply@urbanvoyage.com");

            mailSender.send(mimeMessage);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
        }
    }

    private String createHtmlEmailContent(String verificationCode) {
        return "<!DOCTYPE html>"
                + "<html lang='en'>"
                + "<head>"
                + "<meta charset='UTF-8'>"
                + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                + "<title>Email Verification</title>"
                + "<style>"
                + "body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }"
                + ".container { max-width: 600px; margin: 0 auto; padding: 20px; }"
                + ".header { background-color: #06b6d4; color: white; padding: 20px; text-align: center; }"
                + ".content { background-color: #f9f9f9; padding: 20px; border-radius: 5px; }"
                + ".verification-code { font-size: 24px; font-weight: bold; text-align: center; margin: 20px 0; padding: 10px; background-color: #e0e0e0; border-radius: 5px; }"
                + ".footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }"
                + "</style>"
                + "</head>"
                + "<body>"
                + "<div class='container'>"
                + "<div class='header'>"
                + "<h1>UrbanVoyage Email Verification</h1>"
                + "</div>"
                + "<div class='content'>"
                + "<p>Thank you for choosing UrbanVoyage. To complete your registration, please use the following verification code:</p>"
                + "<div class='verification-code'>" + verificationCode + "</div>"
                + "<p>If you didn't request this verification, please ignore this email.</p>"
                + "</div>"
                + "<div class='footer'>"
                + "<p>&copy; 2024 UrbanVoyage. All rights reserved.</p>"
                + "</div>"
                + "</div>"
                + "</body>"
                + "</html>";
    }


    private final JavaMailSender mailSender;


    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    private JavaMailSender getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);
        mailSender.setUsername(username);
        mailSender.setPassword(password);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "true");

        return mailSender;
    }

    public void sendEmailWithAttachment(String to, String subject, String text, byte[] attachment, String attachmentName) {
        try {
            JavaMailSender mailSender = getJavaMailSender();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setFrom(username);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text);

            helper.addAttachment(attachmentName, new ByteArrayResource(attachment));

            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send email: " + e.getMessage(), e);
        }
    }

    public void testEmailConfig() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo("test@example.com");
        message.setSubject("Test Email");
        message.setText("This is a test email from your application.");
        mailSender.send(message);
    }


    public void sendContactNotificationEmail(String to, String subject, String contactMessage) {
        try {
            JavaMailSender mailSender = getJavaMailSender();
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlMsg = createContactNotificationEmailContent(contactMessage);

            helper.setText(htmlMsg, true);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setFrom("noreply@urbanvoyage.com");

            mailSender.send(mimeMessage);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send contact notification email: " + e.getMessage(), e);
        }
    }

    private String createContactNotificationEmailContent(String contactMessage) {
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
                + "<div class='message'>" + contactMessage + "</div>"
                + "</div>"
                + "<div class='footer'>"
                + "<p>&copy; 2024 UrbanVoyage. All rights reserved.</p>"
                + "</div>"
                + "</div>"
                + "</body>"
                + "</html>";
    }

    public void sendOTPEmail(String to, String otp) {
        try {
            JavaMailSender mailSender = getJavaMailSender();
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlMsg = createOTPEmailContent(otp);

            helper.setText(htmlMsg, true);
            helper.setTo(to);
            helper.setSubject("UrbanVoyage Password Reset OTP");
            helper.setFrom("noreply@urbanvoyage.com");

            mailSender.send(mimeMessage);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send OTP email: " + e.getMessage(), e);
        }
    }

    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private String createOTPEmailContent(String otp) {
        return "<!DOCTYPE html>"
                + "<html lang='en'>"
                + "<head>"
                + "<meta charset='UTF-8'>"
                + "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                + "<title>Password Reset OTP</title>"
                + "<style>"
                + "body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }"
                + ".container { max-width: 600px; margin: 0 auto; padding: 20px; }"
                + ".header { background-color: #06b6d4; color: white; padding: 20px; text-align: center; }"
                + ".content { background-color: #f9f9f9; padding: 20px; border-radius: 5px; }"
                + ".otp { font-size: 24px; font-weight: bold; text-align: center; margin: 20px 0; padding: 10px; background-color: #e0e0e0; border-radius: 5px; }"
                + ".footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }"
                + "</style>"
                + "</head>"
                + "<body>"
                + "<div class='container'>"
                + "<div class='header'>"
                + "<h1>UrbanVoyage Password Reset</h1>"
                + "</div>"
                + "<div class='content'>"
                + "<p>You have requested to reset your password. Please use the following OTP to complete the process:</p>"
                + "<div class='otp'>" + otp + "</div>"
                + "<p>If you didn't request this password reset, please ignore this email.</p>"
                + "</div>"
                + "<div class='footer'>"
                + "<p>&copy; 2024 UrbanVoyage. All rights reserved.</p>"
                + "</div>"
                + "</div>"
                + "</body>"
                + "</html>";
    }


    public void sendEmail(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }

    public void sendAdminVerificationEmail(String toEmail, String token, UserDTO adminUser) {
        String subject = "Verify Admin Registration";
        String verificationLink = "http://localhost:4200/verify-admin?token=" + token; // Adjust this URL
        String body = "A new admin user wants to register:\n\n" +
                "Name: " + adminUser.getFirstName() + " " + adminUser.getLastName() + "\n" +
                "Email: " + adminUser.getEmail() + "\n\n" +
                "To approve this registration, click the following link:\n" +
                verificationLink;

        sendEmail(toEmail, subject, body);
    }


}