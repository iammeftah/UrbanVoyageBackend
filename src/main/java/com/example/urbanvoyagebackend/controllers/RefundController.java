package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.dto.RequestRefundDTO;
import com.example.urbanvoyagebackend.entity.payment.RequestRefund;
import com.example.urbanvoyagebackend.service.travel.RefundService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/refunds")
@CrossOrigin(origins = "http://localhost:4200")
public class RefundController {

    @Autowired
    private RefundService refundService;

    @Autowired
    private PaymentController paymentController;

    @GetMapping("/requests")
    public ResponseEntity<List<RequestRefundDTO>> getRefundRequests() {
        List<RequestRefundDTO> requests = refundService.getAllRefundRequests();
        return ResponseEntity.ok(requests);
    }

    @PostMapping("/approve/{requestId}")
    public ResponseEntity<?> approveRefund(@PathVariable Long requestId) {
        try {
            RequestRefund refundRequest = refundService.approveRefund(requestId);

            // Use the existing refund logic in PaymentController
            Map<String, Long> payload = Map.of("reservationId", refundRequest.getPassenger().getReservation().getReservationID());
            return paymentController.refundPayment(payload);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Error approving refund: " + e.getMessage()));
        }
    }

    @PostMapping("/reject/{requestId}")
    public ResponseEntity<?> rejectRefund(@PathVariable Long requestId) {
        try {
            refundService.rejectRefund(requestId);
            return ResponseEntity.ok(Map.of("status", "success", "message", "Refund rejected successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Error rejecting refund: " + e.getMessage()));
        }
    }
}