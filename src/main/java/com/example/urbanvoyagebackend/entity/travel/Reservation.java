package com.example.urbanvoyagebackend.entity.travel;


import com.example.urbanvoyagebackend.entity.users.User;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "reservations")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Reservation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long reservationID;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnoreProperties("reservations")
    private User user;

    @ManyToOne
    @JoinColumn(name = "route_id", nullable = false)
    @JsonIgnoreProperties("reservations")
    private Route route;


    @Column(nullable = false)
    private Date reservationDate;

    @Enumerated(EnumType.STRING)
    private ReservationStatus status;

    @Enumerated(EnumType.STRING)
    private SeatType seatType;


    // Constructors, getters, and setters

    public Reservation() {}

    public Reservation(User user, Route route, Date reservationDate) {
        this.user = user;
        this.route = route;
        this.reservationDate = reservationDate;
        this.status = ReservationStatus.PENDING;
        this.seatType = SeatType.STANDARD;

    }

    // Getters and setters for all fields

    public boolean createReservation() {
        // Implement reservation creation logic
        return true;
    }

    public boolean cancelReservation() {
        // Implement reservation cancellation logic
        return true;
    }

    public enum ReservationStatus {
        PENDING,
        CONFIRMED,
        CANCELLED,
        REFUND_APPROVED, REFUND_REJECTED, REFUND_REQUESTED, REFUNDED
    }

    public enum SeatType {
        STANDARD, PREMIUM, VIP
    }


    public Long getReservationID() {
        return reservationID;
    }

    public void setReservationID(Long reservationID) {
        this.reservationID = reservationID;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Route getRoute() {
        return route;
    }

    public void setRoute(Route route) {
        this.route = route;
    }

    public Date getReservationDate() {
        return reservationDate;
    }

    public void setReservationDate(Date reservationDate) {
        this.reservationDate = reservationDate;
    }

    public ReservationStatus getStatus() {
        return status;
    }

    public void setStatus(ReservationStatus status) {
        this.status = status;
    }

    public SeatType getSeatType() {
        return seatType;
    }

    public void setSeatType(SeatType seatType) {
        this.seatType = seatType;
    }

}