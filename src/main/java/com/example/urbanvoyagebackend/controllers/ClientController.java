package com.example.urbanvoyagebackend.controllers;


import com.example.urbanvoyagebackend.dto.ReservationDTO;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.travel.Schedule;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.service.travel.ReservationService;
import com.example.urbanvoyagebackend.service.travel.ScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/client")
public class ClientController {
    @Autowired
    private ScheduleService scheduleService;

    @Autowired
    private ReservationService reservationService;

    @GetMapping("/search")
    public ResponseEntity<List<Schedule>> searchRoutes(
            @RequestParam String departureCity,
            @RequestParam String arrivalCity,
            @RequestParam @DateTimeFormat(pattern="yyyy-MM-dd") Date date) {
        List<Schedule> schedules = scheduleService.findSchedules(departureCity, arrivalCity, date);
        return ResponseEntity.ok(schedules);
    }

    @PostMapping("/book")
    public ResponseEntity<?> bookTicket(@RequestBody ReservationDTO reservationDTO, Authentication authentication) {
        // Set the user from the authentication object
        // Create the reservation
        Reservation createdReservation = reservationService.createReservation(reservationDTO);
        return ResponseEntity.ok(createdReservation);
    }

    @GetMapping("/reservations")
    public ResponseEntity<List<Reservation>> getUserReservations(Authentication authentication) {
        // Get the user from the authentication object
        User user = (User) authentication.getPrincipal();
        List<Reservation> reservations = reservationService.getUserReservations(user);
        return ResponseEntity.ok(reservations);
    }

    @PostMapping("/cancel/{reservationId}")
    public ResponseEntity<?> cancelReservation(@PathVariable Long reservationId) {
        boolean cancelled = reservationService.cancelReservation(reservationId);
        if (cancelled) {
            return ResponseEntity.ok("Reservation cancelled successfully");
        } else {
            return ResponseEntity.badRequest().body("Failed to cancel reservation");
        }
    }
}