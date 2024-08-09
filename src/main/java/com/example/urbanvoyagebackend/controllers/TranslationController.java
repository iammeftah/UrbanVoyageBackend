package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.models.TranslationRequest;
import com.example.urbanvoyagebackend.service.travel.TranslationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/translate")
public class TranslationController {
    private final TranslationService translationService;
    private static final Logger logger = LoggerFactory.getLogger(TranslationService.class);

    public TranslationController(TranslationService translationService) {
        this.translationService = translationService;
    }

    @PostMapping
    public ResponseEntity<?> translate(@RequestBody TranslationRequest request) {
        try {
            String translatedText = translationService.translate(request.getText(), request.getTargetLanguage());
            Map<String, String> response = new HashMap<>();
            response.put("translatedText", translatedText);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error in translation controller", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred during translation");
        }
    }
}