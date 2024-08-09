package com.example.urbanvoyagebackend.repository.travel;


import com.example.urbanvoyagebackend.entity.travel.Route;
import com.example.urbanvoyagebackend.entity.travel.Schedule;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

public interface ScheduleRepository extends JpaRepository<Schedule, Long> {
    List<Schedule> findByRouteDepartureCityAndRouteArrivalCityAndDepartureTimeAfter(String departureCity, String arrivalCity, Date date);

    @Query("SELECT s FROM Schedule s WHERE s.route.routeID = :routeId AND s.departureTime > CURRENT_TIMESTAMP")
    List<Schedule> findActiveSchedulesByRouteId(Long routeId);

    List<Schedule> findByRouteRouteID(Long routeId);

    Schedule findByRouteAndDepartureTime(Route route, LocalDateTime departureTime);

    @Query("SELECT s FROM Schedule s JOIN s.route r ORDER BY r.boughtTicket DESC")
    List<Schedule> findTopSchedulesByBoughtTickets(Pageable pageable);
}