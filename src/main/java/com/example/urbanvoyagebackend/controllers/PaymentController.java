package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.entity.payment.Payment;
import com.example.urbanvoyagebackend.entity.payment.RequestRefund;
import com.example.urbanvoyagebackend.entity.travel.Passenger;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.travel.Route;
import com.example.urbanvoyagebackend.models.CheckoutRequest;
import com.example.urbanvoyagebackend.repository.travel.PaymentRepository;
import com.example.urbanvoyagebackend.repository.travel.RefundRequestRepository;
import com.example.urbanvoyagebackend.repository.travel.ReservationRepository;
import com.example.urbanvoyagebackend.repository.travel.RouteRepository;
import com.example.urbanvoyagebackend.service.media.EmailService;
import com.example.urbanvoyagebackend.service.travel.PassengerService;
import com.example.urbanvoyagebackend.service.travel.PaymentService;
import com.example.urbanvoyagebackend.service.travel.TicketService;
import com.stripe.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.checkout.Session;
import com.stripe.param.checkout.SessionCreateParams;

import java.math.BigDecimal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.stripe.model.Refund;
import com.stripe.param.RefundCreateParams;

@RestController
@RequestMapping("/api/payment")
@CrossOrigin(origins = "http://localhost:4200")
public class PaymentController {

    @Value("${stripe.api.key}")
    private String stripeApiKey;

    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private PassengerService passengerService;

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private RefundRequestRepository refundRequestRepository;

    public PaymentController(ReservationRepository reservationRepository) {
    }

    @PostMapping("/create-checkout-session")
    public ResponseEntity<Map<String, String>> createCheckoutSession(@RequestBody CheckoutRequest checkoutRequest) throws StripeException {
        System.out.println("Received request to create checkout session");
        System.out.println("Product: " + checkoutRequest.getProductName());
        System.out.println("Amount: " + checkoutRequest.getAmount());

        Stripe.apiKey = stripeApiKey;

        SessionCreateParams params = SessionCreateParams.builder()

                .setMode(SessionCreateParams.Mode.PAYMENT)
                .setSuccessUrl("http://localhost:4200/success?session_id={CHECKOUT_SESSION_ID}")
                .setCancelUrl("http://localhost:4200/routes")
                .addLineItem(SessionCreateParams.LineItem.builder()
                        .setQuantity(1L)
                        .setPriceData(SessionCreateParams.LineItem.PriceData.builder()
                                .setCurrency("mad")
                                .setUnitAmount(checkoutRequest.getAmount().multiply(new BigDecimal(100)).longValue())
                                .setProductData(SessionCreateParams.LineItem.PriceData.ProductData.builder()
                                        .setName(checkoutRequest.getProductName())
                                        .build())
                                .build())
                        .build())
                .setClientReferenceId(checkoutRequest.getReservationId().toString())
                .build();


        Session session = Session.create(params);
        System.out.println("Created session with ID: " + session.getId());
        System.out.println("Session URL: " + session.getUrl());



        Map<String, String> responseData = new HashMap<>();
        responseData.put("id", session.getId());
        return ResponseEntity.ok(responseData);
    }

    @Autowired
    private TicketService ticketService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private RouteRepository routeRepository;

    @PostMapping("/confirm-payment")
    public ResponseEntity<?> confirmPayment(@RequestBody Map<String, String> payload) {
        String sessionId = payload.get("sessionId");
        Map<String, String> response = new HashMap<>();

        try {
            Stripe.apiKey = stripeApiKey;
            Session session = Session.retrieve(sessionId);

            if ("complete".equals(session.getStatus())) {
                String reservationId = session.getClientReferenceId();
                Reservation reservation = reservationRepository.findById(Long.parseLong(reservationId))
                        .orElseThrow(() -> new RuntimeException("Reservation not found"));

                reservation.setStatus(Reservation.ReservationStatus.CONFIRMED);

                // Save the payment information
                Payment payment = new Payment();
                payment.setReservation(reservation);
                payment.setAmount(session.getAmountTotal() / 100.0); // Stripe amounts are in cents
                payment.setStatus("COMPLETED");
                payment.setPaymentDate(new Date());
                payment.setStripePaymentIntentId(session.getPaymentIntent());

                // Retrieve the Charge ID
                if (session.getPaymentIntent() != null) {
                    try {
                        PaymentIntent paymentIntent = PaymentIntent.retrieve(session.getPaymentIntent());
                        String chargeId = paymentIntent.getLatestCharge();
                        if (chargeId != null) {
                            payment.setStripeChargeId(chargeId);
                        }
                    } catch (StripeException e) {
                        // Log the error but continue with saving the payment
                        System.err.println("Error retrieving Stripe Charge ID: " + e.getMessage());
                    }
                }

                paymentService.savePayment(payment);

                Route route = reservation.getRoute();
                System.out.println("Increasing bought ticket count for route: " + route.getRouteID());
                route.increaseBoughtTicket();
                Route savedRoute = routeRepository.save(route);
                System.out.println("Updated bought ticket count: " + savedRoute.getBoughtTicket());

                reservationRepository.save(reservation);

                // Generate ticket PDF
                Passenger passenger = passengerService.getPassengerByReservation(reservation);
                byte[] ticketPdf = ticketService.generateTicket(reservation, passenger);

                // Send email with ticket
                emailService.sendEmailWithAttachment(
                        passenger.getEmail(),
                        "Your Travel Ticket",
                        "Thank you for your purchase. Please find your ticket attached.",
                        ticketPdf,
                        "UrbanVoyageTicket.pdf"
                );

                // Set up the response with PDF content
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_PDF);
                headers.setContentDispositionFormData("attachment", "ticket.pdf");

                return ResponseEntity.ok()
                        .headers(headers)
                        .body(ticketPdf);
            } else {
                response.put("status", "failure");
                response.put("message", "Payment was not successful");
                return ResponseEntity.badRequest().body(response);
            }

        } catch (Exception e) {
            e.printStackTrace();
            response.put("status", "error");
            response.put("message", "Error confirming payment: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/cancel-payment")
    public ResponseEntity<Map<String, String>> cancelPayment(@RequestBody Map<String, String> payload) {
        String sessionId = payload.get("sessionId");
        Map<String, String> response = new HashMap<>();

        try {
            Stripe.apiKey = stripeApiKey;
            Session session = Session.retrieve(sessionId);

            String reservationId = session.getClientReferenceId();
            Reservation reservation = reservationRepository.findById(Long.parseLong(reservationId))
                    .orElseThrow(() -> new RuntimeException("Reservation not found"));

            reservation.setStatus(Reservation.ReservationStatus.CANCELLED);
            reservationRepository.save(reservation);

            response.put("status", "success");
            response.put("message", "Payment cancelled and reservation updated");

            return ResponseEntity.ok(response);
        } catch (StripeException e) {
            response.put("status", "error");
            response.put("message", "Error cancelling payment: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/refund")
    public ResponseEntity<?> refundPayment(@RequestBody Map<String, Long> payload) {
        Long reservationId = payload.get("reservationId");
        if (reservationId == null) {
            return ResponseEntity.badRequest().body("Reservation ID is required");
        }

        try {
            Reservation reservation = reservationRepository.findById(reservationId)
                    .orElseThrow(() -> new RuntimeException("Reservation not found for ID: " + reservationId));
            System.out.println("Found reservation: " + reservation);

            Payment payment = paymentService.findByReservation(reservation);
            System.out.println("Found payment: " + payment);
            System.out.println("Stripe Payment Intent ID: " + payment.getStripePaymentIntentId());
            System.out.println("Stripe Charge ID: " + payment.getStripeChargeId());

            Stripe.apiKey = stripeApiKey;

            // Use the Charge ID for refund, not the Payment Intent ID
            String chargeId = payment.getStripeChargeId();
            if (chargeId == null || chargeId.isEmpty()) {
                throw new RuntimeException("No Stripe Charge ID found for this payment");
            }

            Charge charge = Charge.retrieve(chargeId);

            if (charge.getRefunded()) {
                // The payment has already been refunded in Stripe
                reservation.setStatus(Reservation.ReservationStatus.REFUNDED);
                reservationRepository.save(reservation);

                payment.setStatus("REFUNDED");
                paymentService.savePayment(payment);

                Map<String, String> response = new HashMap<>();
                response.put("status", "success");
                response.put("message", "Payment was already refunded. Local records updated.");
                return ResponseEntity.ok(response);
            }

            // Proceed with refund if not already refunded
            RefundCreateParams params = RefundCreateParams.builder()
                    .setCharge(chargeId)
                    .build();

            Refund refund = Refund.create(params);

            reservation.setStatus(Reservation.ReservationStatus.REFUNDED);
            reservationRepository.save(reservation);

            payment.setStatus("REFUNDED");
            paymentService.savePayment(payment);

            Map<String, String> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Refund processed successfully");
            return ResponseEntity.ok(response);
        } catch (StripeException e) {
            e.printStackTrace();
            Map<String, String> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Error processing refund: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            e.printStackTrace();
            Map<String, String> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Unexpected error: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }


    @PostMapping("/request-refund")
    public ResponseEntity<?> requestRefund(@RequestBody Map<String, Object> payload) {
        System.out.println("Received refund request payload: " + payload);
        Object reservationIdObj = payload.get("reservationId");
        Object motifObj = payload.get("motif");

        if (reservationIdObj == null || motifObj == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "reservationId and motif are required"));
        }

        try {
            Long reservationId = reservationIdObj instanceof Number ? ((Number) reservationIdObj).longValue() : Long.parseLong(reservationIdObj.toString());
            String motif = motifObj.toString();

            Reservation reservation = reservationRepository.findById(reservationId)
                    .orElseThrow(() -> new RuntimeException("Reservation not found"));

            Passenger passenger = passengerService.getPassengerByReservation(reservation);

            RequestRefund refundRequest = new RequestRefund(passenger, motif);
            refundRequestRepository.save(refundRequest);

            reservation.setStatus(Reservation.ReservationStatus.REFUND_REQUESTED);


            reservationRepository.save(reservation);

            return ResponseEntity.ok(Map.of("status", "success", "message", "Refund request submitted successfully"));
            // ... rest of the method remains the same
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid reservationId format: " + reservationIdObj));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }
}