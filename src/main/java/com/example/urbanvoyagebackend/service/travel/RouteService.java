package com.example.urbanvoyagebackend.service.travel;


import com.example.urbanvoyagebackend.entity.travel.Route;
import com.example.urbanvoyagebackend.entity.travel.Schedule;
import com.example.urbanvoyagebackend.repository.travel.RouteRepository;
import com.example.urbanvoyagebackend.repository.travel.ScheduleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class RouteService {
    @Autowired
    private RouteRepository routeRepository;

    @Autowired
    private ScheduleRepository scheduleRepository;

    public List<Route> getAllRoutes() {
        return routeRepository.findAll();
    }

    public Route addRoute(Route route) {
        System.out.println("Route added");
        return routeRepository.save(route);
    }

    public Route updateRoute(Long id, Route route) {
        route.setRouteID(id);
        return routeRepository.save(route);
    }

    public void deleteRoute(Long id) {
        Route route = routeRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Route with id " + id + " not found"));

        List<Schedule> activeSchedules = scheduleRepository.findActiveSchedulesByRouteId(id);
        if (!activeSchedules.isEmpty()) {
            throw new IllegalStateException("Cannot delete route with active schedules");
        }

        routeRepository.deleteById(id);
    }

    public List<Route>  findByDepartureAndArrivalCity(String departure, String arrival) {
        return routeRepository.findByDepartureCityAndArrivalCity(departure,arrival);
    }

    public Page<Route> getAllRoutesPaginated(int page, int size) {
        Pageable paging = PageRequest.of(page, size);
        return routeRepository.findAll(paging);
    }

    public Page<Route> searchRoutes(String departureCity, String arrivalCity, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        if (departureCity != null && !departureCity.isEmpty() && arrivalCity != null && !arrivalCity.isEmpty()) {
            return routeRepository.findByDepartureCityContainingIgnoreCaseAndArrivalCityContainingIgnoreCase(departureCity, arrivalCity, pageable);
        } else if (departureCity != null && !departureCity.isEmpty()) {
            return routeRepository.findByDepartureCityContainingIgnoreCase(departureCity, pageable);
        } else if (arrivalCity != null && !arrivalCity.isEmpty()) {
            return routeRepository.findByArrivalCityContainingIgnoreCase(arrivalCity, pageable);
        } else {
            return routeRepository.findAll(pageable);
        }
    }
}