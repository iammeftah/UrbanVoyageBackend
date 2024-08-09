package com.example.urbanvoyagebackend.service.travel;


import com.example.urbanvoyagebackend.dto.ReservationDTO;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.example.urbanvoyagebackend.entity.travel.Route;
import com.example.urbanvoyagebackend.entity.travel.Schedule;
import com.example.urbanvoyagebackend.entity.users.User;
import com.example.urbanvoyagebackend.repository.travel.ReservationRepository;
import com.example.urbanvoyagebackend.repository.travel.RouteRepository;
import com.example.urbanvoyagebackend.repository.travel.ScheduleRepository;
import com.example.urbanvoyagebackend.repository.users.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

@Service
public class ReservationService {
    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RouteRepository routeRepository;

    @Autowired
    private ScheduleRepository scheduleRepository;


    @Transactional
    public Reservation createReservation(ReservationDTO reservationDTO) {
        try {
            System.out.println("ReservationService: Starting reservation creation");
            User user = userRepository.findById(reservationDTO.getUserId())
                    .orElseThrow(() -> new RuntimeException("User not found with ID: " + reservationDTO.getUserId()));
            System.out.println("ReservationService: User found");

            Route route = routeRepository.findById(reservationDTO.getRouteId())
                    .orElseThrow(() -> new RuntimeException("Route not found with ID: " + reservationDTO.getRouteId()));
            System.out.println("ReservationService: Route found");

            // Find or create schedule
            Schedule schedule = findOrCreateSchedule(route, reservationDTO);
            System.out.println("ReservationService: Schedule found or created");

            if (schedule.getAvailableSeats() <= 0) {
                throw new IllegalStateException("No available seats for this schedule");
            }

            Reservation reservation = new Reservation();
            reservation.setUser(user);
            reservation.setRoute(route);
            reservation.setReservationDate(new Date());
            reservation.setStatus(Reservation.ReservationStatus.PENDING);
            reservation.setSeatType(reservationDTO.getSeatType() != null ? reservationDTO.getSeatType() : Reservation.SeatType.STANDARD);

            schedule.setAvailableSeats(schedule.getAvailableSeats() - 1);
            scheduleRepository.save(schedule);
            System.out.println("ReservationService: Schedule updated");

            Reservation savedReservation = reservationRepository.save(reservation);
            System.out.println("ReservationService: Reservation saved successfully");

            return savedReservation;
        } catch (Exception e) {
            System.err.println("ReservationService: Error in createReservation: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Autowired
    private DistanceService distanceService;

    @Autowired
    private PricingService pricingService;

    private Schedule findOrCreateSchedule(Route route, ReservationDTO reservationDTO) {
        Schedule schedule = scheduleRepository.findByRouteAndDepartureTime(route, reservationDTO.getDepartureTime());
        if (schedule == null) {
            schedule = new Schedule();
            schedule.setRoute(route);
            schedule.setDepartureTime(reservationDTO.getDepartureTime());

            // Use the distance calculated in the frontend
            double distance = reservationDTO.getDistance();

            // Calculate duration (assuming average speed of 60 km/h)
            long durationMinutes = Math.round((distance / 60) * 60);

            // Set arrival time
            LocalDateTime arrivalTime = reservationDTO.getDepartureTime().plusMinutes(durationMinutes);
            schedule.setArrivalTime(arrivalTime);

            // Calculate price
            BigDecimal price = pricingService.calculateTicketPrice(distance);
            schedule.setSchedulePrice(price);

            // Set available seats (you may want to make this configurable)
            schedule.setAvailableSeats(50);

            schedule = scheduleRepository.save(schedule);
        }
        return schedule;
    }

    public int getAvailableSeats(Long routeId, LocalDateTime departureTime) {
        System.out.println("Reservation Service: getAvailableSeats() triggered");
        Route route = routeRepository.findById(routeId)
                .orElseThrow(() -> new RuntimeException("Route not found with ID: " + routeId));
        Schedule schedule = scheduleRepository.findByRouteAndDepartureTime(route, departureTime);
        if (schedule == null) {
            // If no schedule exists, return a default value or throw an exception
            return 50; // or whatever default value you want to use
        }
        return schedule.getAvailableSeats();
    }

    public Reservation updateReservationSeatType(Long id, String seatType) {
        Reservation reservation = reservationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Reservation not found"));
        if (reservation == null) {
            throw new IllegalArgumentException("Reservation not found");
        }

        try {
            Reservation.SeatType newSeatType = Reservation.SeatType.valueOf(seatType.toUpperCase());
            reservation.setSeatType(newSeatType);
            return reservationRepository.save(reservation);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid seat type");
        }
    }

    public List<Reservation> getUserReservations(User user) {
        System.out.println("ReservationService: Reservertion found (" + user.getReservations() + ")");
        return reservationRepository.findByUser(user);
    }

    public boolean cancelReservation(Long reservationId) {
        reservationRepository.deleteById(reservationId);
        return true;
    }



    public List<Reservation> getAllReservations() {
        System.out.println("ReservationService: getAllReservations method called");
        List<Reservation> reservations = reservationRepository.findAll();
        System.out.println("ReservationService: Number of reservations found: " + reservations.size());
        return reservations;
    }

    @Transactional
    public Reservation updateReservationStatus(Long id, String newStatus) {
        Reservation reservation = reservationRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Reservation not found"));

        Reservation.ReservationStatus currentStatus = reservation.getStatus();
        Reservation.ReservationStatus updatedStatus = Reservation.ReservationStatus.valueOf(newStatus);

        switch (currentStatus) {
            case PENDING:
                if (updatedStatus != Reservation.ReservationStatus.CONFIRMED) {
                    throw new IllegalStateException("Pending reservations can only be confirmed.");
                }
                break;
            case CONFIRMED:
                if (updatedStatus != Reservation.ReservationStatus.CANCELLED) {
                    throw new IllegalStateException("Confirmed reservations can only be cancelled.");
                }
                break;
            case CANCELLED:
                throw new IllegalStateException("Cancelled reservations cannot be modified.");
            default:
                throw new IllegalStateException("Invalid current status.");
        }

        reservation.setStatus(updatedStatus);
        return reservationRepository.save(reservation);
    }

    public void deleteReservation(Long id) {
        if (!reservationRepository.existsById(id)) {
            throw new IllegalArgumentException("Reservation with id " + id + " not found");
        }
        reservationRepository.deleteById(id);
    }

    public Reservation getReservationById(Long id) {
        return reservationRepository.findById(id).orElse(null);
    }

}