package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.dto.ReservationDTO;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.service.travel.ReservationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/reservations")
public class ReservationController {

    @Autowired
    private ReservationService reservationService;

    @GetMapping
    public ResponseEntity<List<ReservationDTO>> getAllReservations() {
        try {
            System.out.println("ReservationController: getAllReservations method called");
            List<Reservation> reservations = reservationService.getAllReservations();
            System.out.println("ReservationController: Number of reservations retrieved: " + reservations.size());

            for (Reservation reservation : reservations) {
                System.out.println("Reservation: ID=" + reservation.getReservationID()
                        + ", Date=" + reservation.getReservationDate()
                        + ", Status=" + reservation.getStatus()
                        + ", UserID=" + reservation.getUser().getUserID()
                        + ", RouteID=" + reservation.getRoute().getRouteID()
                        + ", Departure=" + reservation.getRoute().getDepartureCity()
                        + ", Arrival=" + reservation.getRoute().getArrivalCity());
            }

            List<ReservationDTO> reservationDTOs = reservations.stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

            System.out.println("ReservationController: Number of DTOs created: " + reservationDTOs.size());
            return ResponseEntity.ok(reservationDTOs);
        } catch (Exception e) {
            System.err.println("Error in getAllReservations: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    private ReservationDTO convertToDTO(Reservation reservation) {
        System.out.println("ReservationController: Converting reservation to DTO: " + reservation.getReservationID());
        ReservationDTO dto = new ReservationDTO();
        dto.setReservationID(reservation.getReservationID());
        dto.setReservationDate(reservation.getReservationDate());
        dto.setUserId(reservation.getUser().getUserID());
        dto.setUser(reservation.getUser());
        dto.setRouteId(reservation.getRoute().getRouteID());
        dto.setRoute(reservation.getRoute());
        dto.setStatus(reservation.getStatus());
        dto.setDeparture(reservation.getRoute().getDepartureCity());
        dto.setArrival(reservation.getRoute().getArrivalCity());
        dto.setSeatType(Reservation.SeatType.STANDARD);

        System.out.println("ReservationDTO: ID=" + dto.getReservationID()
                + ", Date=" + dto.getReservationDate()
                + ", Status=" + dto.getStatus()
                + ", UserID=" + dto.getUserId()
                + ", RouteID=" + dto.getRouteId()
                + ", Departure=" + dto.getDeparture()
                + ", Arrival=" + dto.getArrival());


        if (reservation.getUser() != null) {
            dto.setUserId(reservation.getUser().getUserID());
        } else {
            System.out.println("Warning: Reservation " + reservation.getReservationID() + " has no associated user");
            dto.setUserId(null);
        }
        if (reservation.getRoute() != null) {
            dto.setRouteId(reservation.getRoute().getRouteID());
        } else {
            System.out.println("Warning: Reservation " + reservation.getReservationID() + " has no associated route");
            dto.setRouteId(null);
        }
        return dto;
    }

    @PatchMapping("/{id}/seatType")
    public ResponseEntity<?> updateReservationSeatType(@PathVariable Long id, @RequestBody String seatType) {
        try {
            Reservation updatedReservation = reservationService.updateReservationSeatType(id, seatType);
            return ResponseEntity.ok(updatedReservation);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while updating the seat type.");
        }
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<?> updateReservationStatus(@PathVariable Long id, @RequestBody String status) {
        try {
            Reservation updatedReservation = reservationService.updateReservationStatus(id, status);
            return ResponseEntity.ok(updatedReservation);
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while updating the reservation.");
        }
    }

    @PostMapping("/create")
    public ResponseEntity<?> createReservation(@RequestBody ReservationDTO reservationDTO) {
        try {
            Reservation newReservation = reservationService.createReservation(reservationDTO);
            System.out.println("ReservationController: Reservation created successfully");
            return ResponseEntity.ok(newReservation);
        } catch (Exception e) {
            System.err.println("ReservationController: Error creating reservation: " + e.getMessage());
            e.printStackTrace(); // This will print the full stack trace
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while creating the reservation: " + e.getMessage());
        }
    }

    @GetMapping("/availableSeats")
    public ResponseEntity<Integer> getAvailableSeats(@RequestParam Long routeId, @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime departureTime) {
        System.out.println("Reservation Controller: getAvailableSeats() triggered");
        try {
            int availableSeats = reservationService.getAvailableSeats(routeId, departureTime);
            return ResponseEntity.ok(availableSeats);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }


    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteReservation(@PathVariable Long id) {
        reservationService.deleteReservation(id);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/with-users")
    public List<Map<String, Object>> getAllReservationsWithUsers() {
        List<Reservation> reservations = reservationService.getAllReservations();
        return reservations.stream().map(reservation -> {
            Map<String, Object> reservationData = new HashMap<>();
            reservationData.put("id", reservation.getReservationID());
            reservationData.put("status", reservation.getStatus());
            reservationData.put("reservationDate", reservation.getReservationDate());

            User user = reservation.getUser();
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getUserID());
            userData.put("firstName", user.getFirstName());
            userData.put("lastName", user.getLastName());
            // Add other user fields as needed, but be careful not to include sensitive information

            reservationData.put("user", userData);
            return reservationData;
        }).collect(Collectors.toList());
    }



}