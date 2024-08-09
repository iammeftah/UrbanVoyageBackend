package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.entity.travel.Route;
import com.example.urbanvoyagebackend.repository.travel.RouteRepository;
import com.example.urbanvoyagebackend.service.travel.DistanceService;
import com.example.urbanvoyagebackend.service.travel.RouteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/api/routes")
public class RouteController {

    @Autowired
    private RouteService routeService;
    @Autowired
    private RouteRepository routeRepository;
    @Autowired
    private DistanceService distanceService;


    @GetMapping("/search-route")
    public List<Route> findByDepartureAndArrival(@RequestParam String departure, @RequestParam String arrival ) {
        List<Route> routes = routeService.findByDepartureAndArrivalCity(departure, arrival);
        System.out.println("Returning " + routes.size() + " routes");
        System.out.println("Routes: " + routes);
        return routes;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getAllRoutes(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<Route> pageRoutes = routeService.getAllRoutesPaginated(page, size);

        Map<String, Object> response = new HashMap<>();
        response.put("routes", pageRoutes.getContent());
        response.put("currentPage", pageRoutes.getNumber());
        response.put("totalItems", pageRoutes.getTotalElements());
        response.put("totalPages", pageRoutes.getTotalPages());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> searchRoutes(
            @RequestParam(required = false) String departureCity,
            @RequestParam(required = false) String arrivalCity,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Page<Route> pageRoutes = routeService.searchRoutes(departureCity, arrivalCity, page, size);

        Map<String, Object> response = new HashMap<>();
        response.put("routes", pageRoutes.getContent());
        response.put("currentPage", pageRoutes.getNumber());
        response.put("totalItems", pageRoutes.getTotalElements());
        response.put("totalPages", pageRoutes.getTotalPages());

        return ResponseEntity.ok(response);
    }

    @PostMapping
    public Route addRoute(@RequestBody Route route) {
        System.out.println("Route added");
        return routeService.addRoute(route);
    }

    @PutMapping("/{id}")
    public Route updateRoute(@PathVariable Long id, @RequestBody Route route) {
        return routeService.updateRoute(id, route);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteRoute(@PathVariable Long id) {
        try {
            routeService.deleteRoute(id);
            return ResponseEntity.ok().build();
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}