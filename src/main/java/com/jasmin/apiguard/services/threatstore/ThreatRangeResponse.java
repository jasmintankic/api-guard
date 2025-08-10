package com.jasmin.apiguard.services.threatstore;

import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
public class ThreatRangeResponse {
    private Instant from;
    private Instant to;
    private long totalThreatEvents;
    private List<ThreatIpGroup> ips;
}