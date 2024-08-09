package com.example.urbanvoyagebackend.controllers;

import com.example.urbanvoyagebackend.dto.RouteDTO;
import com.example.urbanvoyagebackend.dto.ScheduleDTO;
import com.example.urbanvoyagebackend.entity.travel.Schedule;
import com.example.urbanvoyagebackend.service.travel.ScheduleService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/schedules")
public class ScheduleController {

    @Autowired
    private ScheduleService scheduleService;

    @GetMapping
    public List<ScheduleDTO> getAllSchedules() {
        List<Schedule> schedules = scheduleService.getAllSchedules();
        return schedules.stream().map(this::convertToDTO).collect(Collectors.toList());
    }

    @GetMapping("/top")
    public List<ScheduleDTO> getTopSchedules(@RequestParam(defaultValue = "10") int limit) {
        List<Schedule> topSchedules = scheduleService.getTopSchedulesByBoughtTickets(limit);
        return topSchedules.stream().map(this::convertToDTO).collect(Collectors.toList());
    }


    private ScheduleDTO convertToDTO(Schedule schedule) {
        ScheduleDTO dto = new ScheduleDTO();
        dto.setScheduleID(schedule.getScheduleID());
        dto.setDepartureTime(schedule.getDepartureTime());
        dto.setArrivalTime(schedule.getArrivalTime());
        dto.setAvailableSeats(schedule.getAvailableSeats());

        RouteDTO routeDTO = new RouteDTO();
        routeDTO.setRouteID(schedule.getRoute().getRouteID());
        routeDTO.setDepartureCity(schedule.getRoute().getDepartureCity());
        routeDTO.setArrivalCity(schedule.getRoute().getArrivalCity());
        routeDTO.setDistance(schedule.getRoute().getDistance());
        routeDTO.setBoughtTicket(schedule.getRoute().getBoughtTicket());
        dto.setDuration(schedule.calculateDuration());
        dto.setSchedulePrice(schedule.getSchedulePrice());


        dto.setRoute(routeDTO);

        return dto;
    }

    @PostMapping
    public ResponseEntity<Schedule> addSchedule(@RequestBody Schedule schedule) {
        Schedule newSchedule = scheduleService.addSchedule(schedule);
        return ResponseEntity.ok(newSchedule);
    }

    @PutMapping("/{id}")
    public Schedule updateSchedule(@PathVariable Long id, @RequestBody Schedule schedule) {
        return scheduleService.updateSchedule(id, schedule);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteSchedule(@PathVariable Long id) {
        scheduleService.deleteSchedule(id);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/route/{routeId}")
    public ResponseEntity<List<ScheduleDTO>> getSchedulesByRouteId(@PathVariable Long routeId) {
        List<Schedule> schedules = scheduleService.findByRouteId(routeId);
        List<ScheduleDTO> scheduleDTOs = schedules.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(scheduleDTOs);
    }

    // In ScheduleController.java

    @PatchMapping("/{id}/availableSeats")
    public ResponseEntity<Schedule> updateAvailableSeats(@PathVariable Long id, @RequestBody Map<String, Integer> payload) {
        Integer newAvailableSeats = payload.get("availableSeats");
        if (newAvailableSeats == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            Schedule updatedSchedule = scheduleService.updateAvailableSeats(id, newAvailableSeats);
            return ResponseEntity.ok(updatedSchedule);
        } catch (EntityNotFoundException e) {
            return ResponseEntity.notFound().build();
        }
    }

}