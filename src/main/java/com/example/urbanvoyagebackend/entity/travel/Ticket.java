package com.example.urbanvoyagebackend.entity.travel;


import jakarta.persistence.*;

@Entity
@Table(name = "tickets")
public class Ticket {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long ticketID;

    @OneToOne
    @JoinColumn(name = "reservation_id", nullable = false)
    private Reservation reservation;

    @Column(nullable = false)
    private int seatNumber;

    @Column(nullable = false)
    private double ticketPrice;

    // Constructors, getters, and setters

    public Ticket() {}

    public Ticket(Reservation reservation, int seatNumber, double ticketPrice) {
        this.reservation = reservation;
        this.seatNumber = seatNumber;
        this.ticketPrice = ticketPrice;
    }

    // Getters and setters for all fields

    public void generateTicket() {
        // Implement ticket generation logic
    }


    public Long getTicketID() {
        return ticketID;
    }

    public void setTicketID(Long ticketID) {
        this.ticketID = ticketID;
    }

    public Reservation getReservation() {
        return reservation;
    }

    public void setReservation(Reservation reservation) {
        this.reservation = reservation;
    }

    public int getSeatNumber() {
        return seatNumber;
    }

    public void setSeatNumber(int seatNumber) {
        this.seatNumber = seatNumber;
    }

    public double getTicketPrice() {
        return ticketPrice;
    }

    public void setTicketPrice(double ticketPrice) {
        this.ticketPrice = ticketPrice;
    }
}
