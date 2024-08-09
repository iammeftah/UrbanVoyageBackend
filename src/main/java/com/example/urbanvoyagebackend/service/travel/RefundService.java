package com.example.urbanvoyagebackend.service.travel;

import com.example.urbanvoyagebackend.dto.RequestRefundDTO;
import com.example.urbanvoyagebackend.entity.payment.RequestRefund;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.repository.travel.RefundRequestRepository;
import com.example.urbanvoyagebackend.repository.travel.ReservationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class RefundService {

    @Autowired
    private RefundRequestRepository refundRequestRepository;

    @Autowired
    private ReservationRepository reservationRepository;

    public List<RequestRefundDTO> getAllRefundRequests() {
        List<RequestRefund> requests = refundRequestRepository.findAll();
        return requests.stream()
                .map(RequestRefundDTO::fromEntity)
                .collect(Collectors.toList());
    }

    public RequestRefund approveRefund(Long requestId) {
        RequestRefund refundRequest = refundRequestRepository.findById(requestId)
                .orElseThrow(() -> new RuntimeException("Refund request not found"));
        refundRequest.setStatus(RequestRefund.RefundStatus.APPROVED);
        refundRequestRepository.save(refundRequest);

        // Update reservation status
        Reservation reservation = refundRequest.getPassenger().getReservation();
        reservation.setStatus(Reservation.ReservationStatus.REFUND_APPROVED);
        reservationRepository.save(reservation);

        return refundRequest;
    }

    public void rejectRefund(Long requestId) {
        RequestRefund refundRequest = refundRequestRepository.findById(requestId)
                .orElseThrow(() -> new RuntimeException("Refund request not found"));
        refundRequest.setStatus(RequestRefund.RefundStatus.REJECTED);
        refundRequestRepository.save(refundRequest);

        // Update reservation status
        Reservation reservation = refundRequest.getPassenger().getReservation();
        reservation.setStatus(Reservation.ReservationStatus.REFUND_REJECTED);
        reservationRepository.save(reservation);
    }
}