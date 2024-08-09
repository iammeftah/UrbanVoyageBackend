package com.example.urbanvoyagebackend.dto;

import com.example.urbanvoyagebackend.entity.payment.RequestRefund;
import java.time.LocalDateTime;

public class RequestRefundDTO {
    private Long id;
    private String passengerName;
    private Long reservationId;
    private LocalDateTime requestDate;
    private String motif;
    private RequestRefund.RefundStatus status;

    // Constructors

    public static RequestRefundDTO fromEntity(RequestRefund refundRequest) {
        RequestRefundDTO dto = new RequestRefundDTO();
        dto.setId(refundRequest.getId());
        dto.setPassengerName(refundRequest.getPassenger().getFirstName() + " " + refundRequest.getPassenger().getLastName());
        dto.setReservationId(refundRequest.getPassenger().getReservation().getReservationID());
        dto.setRequestDate(refundRequest.getRequestDate());
        dto.setMotif(refundRequest.getMotif());
        dto.setStatus(refundRequest.getStatus());
        dto.setRequestDate(refundRequest.getRequestDate());

        return dto;
    }

    // Getters and setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPassengerName() {
        return passengerName;
    }

    public void setPassengerName(String passengerName) {
        this.passengerName = passengerName;
    }

    public Long getReservationId() {
        return reservationId;
    }

    public void setReservationId(Long reservationId) {
        this.reservationId = reservationId;
    }

    public LocalDateTime getRequestDate() {
        return requestDate;
    }

    public void setRequestDate(LocalDateTime requestDate) {
        this.requestDate = requestDate;
    }

    public String getMotif() {
        return motif;
    }

    public void setMotif(String motif) {
        this.motif = motif;
    }

    public RequestRefund.RefundStatus getStatus() {
        return status;
    }

    public void setStatus(RequestRefund.RefundStatus status) {
        this.status = status;
    }
}