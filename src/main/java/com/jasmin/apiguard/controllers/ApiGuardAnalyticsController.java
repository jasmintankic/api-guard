package com.jasmin.apiguard.controllers;

import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.EventAnalyticsResponse;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.jasmin.apiguard.services.AnalyticsService;

import java.time.LocalDateTime;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api-guard-analytics")
public class ApiGuardAnalyticsController {
    private final AnalyticsService analyticsService;

    @GetMapping("/event-count")
    public EventAnalyticsResponse getEventStats(@RequestParam("from") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
                                                @RequestParam("to") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {
        return analyticsService.getEventStats(from, to);
    }
}
