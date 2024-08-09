package com.example.urbanvoyagebackend.service.media;


import com.example.urbanvoyagebackend.entity.media.FAQ;
import com.example.urbanvoyagebackend.repository.media.FAQRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class FaqService {

    @Autowired
    private FAQRepository faqRepository;

    public List<FAQ> getAllFAQs() {
        return faqRepository.findAll();
    }

    public Optional<FAQ> getFAQById(Long id) {
        return faqRepository.findById(id);
    }

    public FAQ createFAQ(FAQ faq) {
        return faqRepository.save(faq);
    }

    public FAQ updateFAQ(Long id, FAQ faqDetails) {
        FAQ faq = faqRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("FAQ not found with id: " + id));

        faq.setQuestion(faqDetails.getQuestion());
        faq.setAnswer(faqDetails.getAnswer());

        return faqRepository.save(faq);
    }

    public void deleteFAQ(Long id) {
        FAQ faq = faqRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("FAQ not found with id: " + id));

        faqRepository.delete(faq);
    }
}