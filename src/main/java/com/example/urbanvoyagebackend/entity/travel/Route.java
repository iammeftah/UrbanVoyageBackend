package com.example.urbanvoyagebackend.entity.travel;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import java.util.Set;

@Entity
@Table(name = "routes")
public class Route {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long routeID;

    @Column(nullable = false)
    private String departureCity;

    @Column(nullable = false)
    private String arrivalCity;

    @Column(nullable = false)
    private double distance;

    @OneToMany(mappedBy = "route")
    @JsonManagedReference
    private Set<Schedule> schedules;

    @JsonIgnore
    @OneToMany(mappedBy = "route")
    private Set<Reservation> reservations;

    @Column(name = "bought_ticket")
    private int boughtTicket = 0;  // Initialize to 0



    // Constructors, getters, and setters

    public Route() {}

    public Route(String departureCity, String arrivalCity, double distance) {
        this.departureCity = departureCity;
        this.arrivalCity = arrivalCity;
        this.distance = distance;
    }

    // Getters and setters for all fields

    public void addSchedule(Schedule schedule) {
        // Implement add schedule logic
    }

    public void deleteSchedule(Schedule schedule) {
        // Implement delete schedule logic
    }

    public Set<Schedule> getSchedules() {
        // Implement get schedules logic
        return schedules;
    }


    public Long getRouteID() {
        return routeID;
    }

    public void setRouteID(Long routeID) {
        this.routeID = routeID;
    }

    public String getDepartureCity() {
        return departureCity;
    }

    public void setDepartureCity(String departureCity) {
        this.departureCity = departureCity;
    }

    public String getArrivalCity() {
        return arrivalCity;
    }

    public void setArrivalCity(String arrivalCity) {
        this.arrivalCity = arrivalCity;
    }

    public double getDistance() {
        return distance;
    }

    public void setDistance(double distance) {
        this.distance = distance;
    }

    public void setSchedules(Set<Schedule> schedules) {
        this.schedules = schedules;
    }

    public Set<Reservation> getReservations() {
        return reservations;
    }

    public void setReservations(Set<Reservation> reservations) {
        this.reservations = reservations;
    }

    public int getBoughtTicket() {
        return boughtTicket;
    }

    public void setBoughtTicket(int boughtTicket) {
        this.boughtTicket = boughtTicket;
    }

    public Route increaseBoughtTicket() {
        this.boughtTicket++;
        return this;
    }
}