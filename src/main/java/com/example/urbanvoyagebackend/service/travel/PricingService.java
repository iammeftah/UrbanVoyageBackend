package com.example.urbanvoyagebackend.service.travel;

import org.springframework.stereotype.Service;
import java.math.BigDecimal;
import java.math.RoundingMode;

@Service
public class PricingService {

    private static final BigDecimal BASE_FARE = new BigDecimal("10.00");
    private static final BigDecimal RATE_PER_KM = new BigDecimal("0.50");
    private static final BigDecimal FUEL_COST_PER_LITER = new BigDecimal("1.20");
    private static final BigDecimal AVG_FUEL_CONSUMPTION = new BigDecimal("0.10"); // Liters per km

    public BigDecimal calculateTicketPrice(double distance) {
        BigDecimal distanceBigDecimal = BigDecimal.valueOf(distance);

        BigDecimal price = BASE_FARE.add(distanceBigDecimal.multiply(RATE_PER_KM));

        // Calculate fuel cost
        BigDecimal fuelCost = distanceBigDecimal.multiply(AVG_FUEL_CONSUMPTION).multiply(FUEL_COST_PER_LITER);
        price = price.add(fuelCost);

        // Round to 2 decimal places
        return price.setScale(2, RoundingMode.HALF_UP);
    }

    // You can add methods to update rates, fuel costs, etc.
}