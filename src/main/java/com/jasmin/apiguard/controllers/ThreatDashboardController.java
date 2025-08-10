package com.jasmin.apiguard.controllers;

import com.jasmin.apiguard.services.threatstore.ThreatQueryService;
import com.jasmin.apiguard.services.threatstore.ThreatRangeResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;

@RestController
@RequestMapping("/dashboard")
@RequiredArgsConstructor
@CrossOrigin(
        origins = "*",          // allow any origin
        allowedHeaders = "*",   // allow any header
        methods = {             // allow all main HTTP methods
                RequestMethod.GET,
                RequestMethod.POST,
                RequestMethod.PUT,
                RequestMethod.DELETE,
                RequestMethod.OPTIONS,
                RequestMethod.PATCH
        }
)
public class ThreatDashboardController {

    private final ThreatQueryService queryService;

    @GetMapping("/threats")
    public ThreatRangeResponse getThreats(
            @RequestParam String from,
            @RequestParam String to,
            @RequestParam(defaultValue = "3") int samplesPerIp) {

        try {
            Instant fromTs = Instant.parse(from);
            Instant toTs = Instant.parse(to);
            return queryService.query(fromTs, toTs, samplesPerIp);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid date-time format. Use ISO-8601, e.g. 2025-08-10T12:00:00Z");
        }
    }

    @GetMapping("/threats/{id}")
    public Map<Object, Object> getThreatDetails(@PathVariable String id) {
        Map<Object, Object> h = queryService.getFullEvent(id);
        if (h == null) {
            throw new IllegalArgumentException("Event not found");
        }
        return h;
    }
}