package com.example.urbanvoyagebackend.entity.users;

import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.travel.Route;
import jakarta.persistence.*;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "clients")
public class Client extends User {

    public Client() {
        super();
        this.addRole(Role.ROLE_CLIENT);
    }

    public Client(String firstName, String lastName, String phoneNumber, String email, String username, String password) {
        super(firstName, lastName, phoneNumber, email, username, password);
        this.addRole(Role.ROLE_CLIENT);
    }

    // Client-specific methods
    public List<Route> searchRoute(String departureCity, String arrivalCity, Date departureDate, TripType tripType, Date returnDate) {
        // Implementation for searching routes
        return null; // Placeholder
    }

    public Reservation bookTicket(Route route) {
        // Implementation for booking a ticket
        return null; // Placeholder
    }

    public boolean cancelReservation(Reservation reservation) {
        // Implementation for canceling a reservation
        return false; // Placeholder
    }

    public List<Reservation> viewReservations() {
        // Implementation for viewing reservations
        return null; // Placeholder
    }
}