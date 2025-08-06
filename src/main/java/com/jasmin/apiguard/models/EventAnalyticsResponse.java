package com.jasmin.apiguard.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EventAnalyticsResponse {
    private long totalEvents;
    private long totalThreats;
    private LocalDateTime from;
    private LocalDateTime to;
    private Map<String, Long> threatsByType;
}