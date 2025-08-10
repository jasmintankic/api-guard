package com.jasmin.apiguard.services.threatstore;

import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Data
public class ThreatIpGroup {
    private String ip;
    private long count;
    private Instant latestAt;
    private List<ThreatSample> samples = new ArrayList<>();
}