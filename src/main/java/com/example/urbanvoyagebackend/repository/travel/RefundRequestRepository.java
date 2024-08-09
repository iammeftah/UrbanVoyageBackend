package com.example.urbanvoyagebackend.repository.travel;// Create a new file named RefundRequestRepository.java in the appropriate package


import com.example.urbanvoyagebackend.entity.payment.RequestRefund;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefundRequestRepository extends JpaRepository<RequestRefund, Long> {
    // You can add custom query methods here if needed
}