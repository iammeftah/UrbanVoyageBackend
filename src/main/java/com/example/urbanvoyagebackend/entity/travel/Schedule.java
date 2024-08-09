package com.example.urbanvoyagebackend.entity.travel;


import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.Temporal;
import java.util.Date;

@Entity
@Table(name = "schedules")
public class Schedule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long scheduleID;

    @ManyToOne
    @JoinColumn(name = "route_id", nullable = false)
    @JsonBackReference
    private Route route;

    @Column(nullable = false , columnDefinition = "TIMESTAMP")
    private LocalDateTime departureTime;

    @Column(nullable = false , columnDefinition = "TIMESTAMP")
    private LocalDateTime arrivalTime;

    @Column(nullable = false)
    private int availableSeats;


    private String duration;

    private BigDecimal schedulePrice;


    // Constructors, getters, and setters

    public Schedule() {}

    public Schedule(Route route, LocalDateTime departureTime, LocalDateTime arrivalTime, int availableSeats) {
        this.route = route;
        this.departureTime = departureTime;
        this.arrivalTime = arrivalTime;
        this.availableSeats = availableSeats;
    }

    // Getters and setters for all fields

    public void updateAvailableSeats(int seats) {
        // Implement update available seats logic
    }

    public boolean isAvailable() {
        // Implement availability check logic
        return availableSeats > 0;
    }

    public Long getScheduleID() {
        return scheduleID;
    }

    public void setScheduleID(Long scheduleID) {
        this.scheduleID = scheduleID;
    }

    public Route getRoute() {
        return route;
    }

    public void setRoute(Route route) {
        this.route = route;
    }

    public LocalDateTime getDepartureTime() {
        return departureTime;
    }

    public void setDepartureTime(LocalDateTime departureTime) {
        this.departureTime = departureTime;
    }

    public LocalDateTime getArrivalTime() {
        return arrivalTime;
    }

    public void setArrivalTime(LocalDateTime arrivalTime) {
        this.arrivalTime = arrivalTime;
    }

    public int getAvailableSeats() {
        return availableSeats;
    }

    public void setAvailableSeats(int availableSeats) {
        this.availableSeats = availableSeats;
    }

    public String getDuration() {
        return duration;
    }

    public void setDuration(String duration) {
        this.duration = duration;
    }

    public String calculateDuration() {
        if (departureTime == null || arrivalTime == null) {
            return "N/A";
        }
        Duration duration = Duration.between(departureTime, arrivalTime);
        long hours = duration.toHours();
        long minutes = duration.toMinutesPart();
        return String.format("%d:%02d", hours, minutes);
    }

    public BigDecimal getSchedulePrice() {
        return schedulePrice;
    }

    public void setSchedulePrice(BigDecimal schedulePrice) {
        this.schedulePrice = schedulePrice;
    }
}