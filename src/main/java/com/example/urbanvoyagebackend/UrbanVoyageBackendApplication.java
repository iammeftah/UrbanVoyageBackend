package com.example.urbanvoyagebackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
//@PropertySource("file:.env")
public class
UrbanVoyageBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(UrbanVoyageBackendApplication.class, args);
    }

}
