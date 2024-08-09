package com.example.urbanvoyagebackend.service.travel;

import org.springframework.stereotype.Service;

@Service
public class DistanceService {

    private static final double EARTH_RADIUS = 6371; // Earth's radius in kilometers

    public double calculateDistance(double lat1, double lon1, double lat2, double lon2) {
        double dLat = deg2rad(lat2 - lat1);
        double dLon = deg2rad(lon2 - lon1);

        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) *
                        Math.sin(dLon / 2) * Math.sin(dLon / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        double d = EARTH_RADIUS * c; // Distance in km

        return d;
    }

    private double deg2rad(double deg) {
        return deg * (Math.PI / 180);
    }
}