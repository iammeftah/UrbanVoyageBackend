package com.example.urbanvoyagebackend.dto;


import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Date;

public class ScheduleDTO {
    private Long scheduleID;
    private LocalDateTime departureTime;
    private LocalDateTime arrivalTime;
    private RouteDTO route;
    private int availableSeats;
    private String duration;
    private BigDecimal  schedulePrice;

    // Getters and setters
    public Long getScheduleID() { return scheduleID; }
    public void setScheduleID(Long scheduleID) { this.scheduleID = scheduleID; }
    public LocalDateTime getDepartureTime() { return departureTime; }
    public void setDepartureTime(LocalDateTime departureTime) { this.departureTime = departureTime; }
    public LocalDateTime getArrivalTime() { return arrivalTime; }
    public void setArrivalTime(LocalDateTime arrivalTime) { this.arrivalTime = arrivalTime; }
    public RouteDTO getRoute() { return route; }
    public void setRoute(RouteDTO route) { this.route = route; }
    public int getAvailableSeats() { return availableSeats;}
    public void setAvailableSeats(int availableSeats) {this.availableSeats=availableSeats;}

    public String getDuration() {
        return duration;
    }

    public void setDuration(String duration) {
        this.duration = duration;
    }

    public BigDecimal getSchedulePrice() {
        return schedulePrice;
    }

    public void setSchedulePrice(BigDecimal schedulePrice) {
        this.schedulePrice = schedulePrice;
    }
}