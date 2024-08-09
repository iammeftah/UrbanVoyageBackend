package com.example.urbanvoyagebackend.models;

import java.math.BigDecimal;

public class CheckoutRequest {
    private String productName;
    private BigDecimal amount;
    private Long reservationId;

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }

    public Long getReservationId() {
        return reservationId;
    }

    public void setReservationId(Long reservationId) {
        this.reservationId = reservationId;
    }

    // Getters and setters
}