package com.example.urbanvoyagebackend.repository.media;

import com.example.urbanvoyagebackend.entity.media.FAQ;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FAQRepository extends JpaRepository<FAQ, Long> {
    List<FAQ> findByQuestionContaining(String keyword);
    List<FAQ> findTop10ByOrderByIdDesc();
}