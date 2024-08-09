package com.example.urbanvoyagebackend.entity.payment;

import com.example.urbanvoyagebackend.entity.travel.Passenger;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "refund_requests")
public class RequestRefund {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "passenger_id", nullable = false)
    private Passenger passenger;


    @Column(nullable = false)
    private String motif;

    @Column(nullable = false)
    private LocalDateTime requestDate;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RefundStatus status;

    public enum RefundStatus {
        PENDING, APPROVED, REJECTED
    }

    // Constructors, getters, and setters

    public RequestRefund() {
    }

    public RequestRefund(Passenger passenger, String motif) {
        this.passenger = passenger;
        this.motif = motif;
        this.requestDate = LocalDateTime.now();
        this.status = RefundStatus.PENDING;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Passenger getPassenger() {
        return passenger;
    }

    public void setPassenger(Passenger passenger) {
        this.passenger = passenger;
    }

    public String getMotif() {
        return motif;
    }

    public void setMotif(String motif) {
        this.motif = motif;
    }

    public LocalDateTime getRequestDate() {
        return requestDate;
    }

    public void setRequestDate(LocalDateTime requestDate) {
        this.requestDate = requestDate;
    }

    public RefundStatus getStatus() {
        return status;
    }

    public void setStatus(RefundStatus status) {
        this.status = status;
    }

    public Long getReservationId() {
        return passenger.getReservation().getReservationID();
    }

    // Getters and setters
    // ...
}