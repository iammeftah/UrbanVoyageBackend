

package com.example.urbanvoyagebackend.service.travel;

import com.example.urbanvoyagebackend.entity.travel.Schedule;
import com.example.urbanvoyagebackend.repository.travel.ScheduleRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class ScheduleService {

    @Autowired
    private ScheduleRepository scheduleRepository;

    public List<Schedule> getAllSchedules() {
        return scheduleRepository.findAll();
    }

    public Schedule addSchedule(Schedule schedule) {
        return scheduleRepository.save(schedule);
    }

    public List<Schedule> findSchedules(String departureCity, String arrivalCity, Date date) {
        return scheduleRepository.findByRouteDepartureCityAndRouteArrivalCityAndDepartureTimeAfter(departureCity, arrivalCity, date);
    }
    public Schedule updateSchedule(Long id, Schedule schedule) {
        schedule.setScheduleID(id);
        return scheduleRepository.save(schedule);
    }

    public void deleteSchedule(Long id) {
        scheduleRepository.deleteById(id);
    }

    public List<Schedule> findByRouteId(Long routeId) {
        return scheduleRepository.findByRouteRouteID(routeId);
    }

    @Transactional
    public Schedule updateAvailableSeats(Long id, int newAvailableSeats) {
        Schedule schedule = scheduleRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Schedule not found"));
        schedule.setAvailableSeats(newAvailableSeats);
        return scheduleRepository.save(schedule);
    }

    public List<Schedule> getTopSchedulesByBoughtTickets(int limit) {
        return scheduleRepository.findTopSchedulesByBoughtTickets(PageRequest.of(0, limit));
    }
}