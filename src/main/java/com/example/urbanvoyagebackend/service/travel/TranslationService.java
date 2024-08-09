package com.example.urbanvoyagebackend.service.travel;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

@Service
public class TranslationService {
    private static final Logger logger = LoggerFactory.getLogger(TranslationService.class);
    private final RestTemplate restTemplate;

    private final String apiUrl = "https://api-free.deepl.com/v2/translate";

    @Value("${deepl.api.key}")
    private String apiKey;

    @Autowired
    public TranslationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String translate(String text, String targetLanguage) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "DeepL-Auth-Key " + apiKey);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("text", text);
        body.add("target_lang", targetLanguage.toUpperCase());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> responseEntity = restTemplate.exchange(
                    apiUrl,
                    HttpMethod.POST,
                    request,
                    Map.class
            );

            if (responseEntity.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> response = responseEntity.getBody();
                if (response != null && response.containsKey("translations")) {
                    List<Map<String, String>> translations = (List<Map<String, String>>) response.get("translations");
                    if (!translations.isEmpty()) {
                        return translations.get(0).get("text");
                    }
                }
                logger.error("Unexpected response format from DeepL API");
            } else {
                logger.error("DeepL API returned status code: " + responseEntity.getStatusCodeValue());
            }
        } catch (Exception e) {
            logger.error("Error calling DeepL API", e);
        }
        return "Translation service unavailable";
    }
}