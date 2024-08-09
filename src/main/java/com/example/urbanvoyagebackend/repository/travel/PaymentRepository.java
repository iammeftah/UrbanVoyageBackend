package com.example.urbanvoyagebackend.repository.travel;

import com.example.urbanvoyagebackend.entity.payment.Payment;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
    Optional<Payment> findByReservation(Reservation reservation);

}
