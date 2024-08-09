package com.example.urbanvoyagebackend.utils;

import com.example.urbanvoyagebackend.models.Location;
import com.google.maps.DirectionsApi;
import com.google.maps.GeoApiContext;
import com.google.maps.model.DirectionsResult;
import com.google.maps.model.TravelMode;

public class DistanceCalculator {

    private static final String GOOGLE_MAPS_API_KEY = "AIzaSyCDjOf_9XM-mSZ9h4Hv9ukO5YCCBIrxIHc";
    private static final GeoApiContext GEO_API_CONTEXT = new GeoApiContext.Builder()
            .apiKey(GOOGLE_MAPS_API_KEY)
            .build();

    public static double calculateDistance(Location departure, Location arrival) {
        try {
            DirectionsResult directionsResult = DirectionsApi.newRequest(GEO_API_CONTEXT)
                    .origin(departure.getLatitude() + "," + departure.getLongitude())
                    .destination(arrival.getLatitude() + "," + arrival.getLongitude())
                    .mode(TravelMode.DRIVING)
                    .await();

            double distance = directionsResult.routes[0].legs[0].distance.inMeters;
            return distance / 1000.0; // Convert to kilometers
        } catch (Exception e) {
            e.printStackTrace();
            return 0.0;
        }
    }
}