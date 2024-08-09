package com.example.urbanvoyagebackend.repository.travel;


import com.example.urbanvoyagebackend.entity.travel.Route;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Date;
import java.util.List;

public interface RouteRepository extends JpaRepository<Route, Long> {
    List<Route> findByDepartureCityAndArrivalCity(String departureCity, String arrivalCity);
    Page<Route> findAll(Pageable pageable);

    Page<Route> findByDepartureCityContainingIgnoreCaseAndArrivalCityContainingIgnoreCase(String departureCity, String arrivalCity, Pageable pageable);
    Page<Route> findByDepartureCityContainingIgnoreCase(String departureCity, Pageable pageable);
    Page<Route> findByArrivalCityContainingIgnoreCase(String arrivalCity, Pageable pageable);
}