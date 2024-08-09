package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.dto.PassengerDTO;
import com.example.urbanvoyagebackend.entity.travel.Passenger;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.repository.travel.ReservationRepository;
import com.example.urbanvoyagebackend.repository.users.UserRepository;
import com.example.urbanvoyagebackend.service.travel.PassengerService;
import com.example.urbanvoyagebackend.service.travel.ReservationService;
import com.example.urbanvoyagebackend.service.users.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/passengers")
public class PassengerController {

    private final PassengerService passengerService;
    private final UserRepository userRepository;
    private final ReservationService reservationService;

    @Autowired
    public PassengerController(PassengerService passengerService , AuthService authService, UserRepository userRepository, ReservationService reservationService) {
        this.passengerService = passengerService;
        this.userRepository = userRepository;
        this.reservationService = reservationService;
    }

    @PostMapping
    public ResponseEntity<Passenger> createPassenger(@RequestBody PassengerDTO passengerDTO) {
        if (passengerDTO.getReservationId() == null) {
            return ResponseEntity.badRequest().body(null);
        }

        Reservation reservation = reservationService.getReservationById(passengerDTO.getReservationId());
        if (reservation == null) {
            return ResponseEntity.notFound().build();
        }

        Passenger passenger = new Passenger();
        // Map DTO fields to Passenger entity
        passenger.setFirstName(passengerDTO.getFirstName());
        passenger.setLastName(passengerDTO.getLastName());
        passenger.setEmail(passengerDTO.getEmail());
        passenger.setPhoneNumber(passengerDTO.getPhoneNumber());
        passenger.setSpecialRequests(passengerDTO.getSpecialRequests());
        passenger.setDepartureCity(passengerDTO.getDepartureCity());
        passenger.setArrivalCity(passengerDTO.getArrivalCity());
        passenger.setSeatType(passengerDTO.getSeatType());
        passenger.setSchedulePrice(passengerDTO.getSchedulePrice());
        passenger.setArrivalTime(passengerDTO.getArrivalTime());
        passenger.setDepartureTime(passengerDTO.getDepartureTime());

        // Set the reservation
        passenger.setReservation(reservation);
        passenger.setReservationId(reservation.getReservationID());

        // Save the passenger, which will also generate and set the serial number and QR code
        Passenger savedPassenger = passengerService.savePassenger(passenger, passenger.getEmail());
        System.out.println("Created passenger " + savedPassenger + " with serial number " + savedPassenger.getSerialNumber());
        return ResponseEntity.ok(savedPassenger);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Passenger> getPassenger(@PathVariable Long id) {
        Passenger passenger = passengerService.getPassengerById(id);
        if (passenger != null) {
            return ResponseEntity.ok(passenger);
        } else {
            return ResponseEntity.notFound().build();
        }
    }


    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Passenger>> getPassengersByUserId(@PathVariable Long userId) {
        Optional<User> user = userRepository.findById(userId);
        List<Passenger> passengers = passengerService.getPassengersByUser(user.orElse(null));
        return ResponseEntity.ok(passengers);
    }

    // Add more endpoints as needed
}