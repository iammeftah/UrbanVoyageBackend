package com.example.urbanvoyagebackend.controllers;


import com.example.urbanvoyagebackend.entity.travel.Route;
import com.example.urbanvoyagebackend.entity.travel.Schedule;
import com.example.urbanvoyagebackend.service.travel.RouteService;
import com.example.urbanvoyagebackend.service.travel.ScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @Autowired
    private RouteService routeService;

    @Autowired
    private ScheduleService scheduleService;

    @PostMapping("/routes")
    public ResponseEntity<Route> addRoute(@RequestBody Route route) {
        Route newRoute = routeService.addRoute(route);
        return ResponseEntity.ok(newRoute);
    }

    @GetMapping("/routes")
    public ResponseEntity<List<Route>> getAllRoutes() {
        List<Route> routes = routeService.getAllRoutes();
        return ResponseEntity.ok(routes);
    }

    @PostMapping("/schedules")
    public ResponseEntity<Schedule> addSchedule(@RequestBody Schedule schedule) {
        Schedule newSchedule = scheduleService.addSchedule(schedule);
        return ResponseEntity.ok(newSchedule);
    }

    // Add more admin functionalities as needed
}