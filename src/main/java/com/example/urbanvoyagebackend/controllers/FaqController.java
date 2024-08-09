package com.example.urbanvoyagebackend.controllers;


import com.example.urbanvoyagebackend.entity.media.FAQ;
import com.example.urbanvoyagebackend.service.media.FaqService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/faqs")
public class FaqController {

    @Autowired
    private FaqService faqService;

    @GetMapping
    public List<FAQ> getAllFAQs() {
        return faqService.getAllFAQs();
    }

    @GetMapping("/{id}")
    public ResponseEntity<FAQ> getFAQById(@PathVariable Long id) {
        return faqService.getFAQById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public FAQ createFAQ(@RequestBody FAQ faq) {
        return faqService.createFAQ(faq);
    }

    @PutMapping("/{id}")
    public ResponseEntity<FAQ> updateFAQ(@PathVariable Long id, @RequestBody FAQ faqDetails) {
        try {
            FAQ updatedFAQ = faqService.updateFAQ(id, faqDetails);
            return ResponseEntity.ok(updatedFAQ);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteFAQ(@PathVariable Long id) {
        try {
            faqService.deleteFAQ(id);
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }
}