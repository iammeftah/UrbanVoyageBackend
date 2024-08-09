package com.example.urbanvoyagebackend.service.travel;

import com.example.urbanvoyagebackend.entity.travel.Passenger;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.repository.travel.PassengerRepository;
import com.example.urbanvoyagebackend.service.users.AuthService;
import com.example.urbanvoyagebackend.utils.QRCodeService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class PassengerService {

    private final PassengerRepository passengerRepository;
    private final AuthService authService;
    private final QRCodeService qrCodeService;

    @Autowired
    public PassengerService(PassengerRepository passengerRepository, AuthService authService, QRCodeService qrCodeService) {
        this.passengerRepository = passengerRepository;
        this.authService = authService;
        this.qrCodeService = qrCodeService;
    }

    private String generateSerialNumber() {
        return UUID.randomUUID().toString();
    }

    @Transactional
    public Passenger savePassenger(Passenger passenger, String userEmail) {
        String serialNumber = generateSerialNumber();
        passenger.setSerialNumber(serialNumber);

        Optional<User> currentUser = authService.getCurrentUser(userEmail);
        if (currentUser.isPresent()) {
            passenger.setCreatedByUser(currentUser.orElse(null));
        }
        System.out.println("PassengerService savePassenger: " + passenger);

        try {
            byte[] qrCode = qrCodeService.generateQRCode(serialNumber, 250, 250);
            // You might want to save this QR code to a file or database
            // For now, we'll just print its length
            System.out.println("QR Code generated, size: " + qrCode.length + " bytes");
        } catch (Exception e) {
            System.err.println("Error generating QR code: " + e.getMessage());
        }

        return passengerRepository.save(passenger);
    }

    public List<Passenger> getAllPassengers() {
        return passengerRepository.findAll();
    }

    public Passenger getPassengerById(Long id) {
        return passengerRepository.findById(id).orElse(null);
    }

    public List<Passenger> getPassengersByUser(User user) {
        return passengerRepository.findByCreatedByUser(user);
    }

    public Passenger getPassengerByReservation(Reservation reservation) {
        return passengerRepository.findByReservation(reservation);
    }


}