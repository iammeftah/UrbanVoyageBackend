package com.example.urbanvoyagebackend.dto;

public class RouteDTO {
    private Long routeID;
    private String departureCity;
    private String arrivalCity;
    private double distance;
    int boughtTicket ;


    // Getters and setters
    public Long getRouteID() { return routeID; }
    public void setRouteID(Long routeID) { this.routeID = routeID; }
    public String getDepartureCity() { return departureCity; }
    public void setDepartureCity(String departureCity) { this.departureCity = departureCity; }
    public String getArrivalCity() { return arrivalCity; }
    public void setArrivalCity(String arrivalCity) { this.arrivalCity = arrivalCity; }
    public double getDistance() { return distance; }
    public void setDistance(double distance) { this.distance = distance; }

    public int getBoughtTicket() {
        return boughtTicket;
    }

    public void setBoughtTicket(int boughtTicket) {
        this.boughtTicket = boughtTicket;
    }
}