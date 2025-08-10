package com.jasmin.apiguard.detectors.ddosattackdetector;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties(prefix = "detectors.ddos")
public class DdosDetectorProperties {
    private boolean enabled = true;
    private String keyPrefix = "ag";

    // Fixed-window TTLs
    private int windowsS1TtlSeconds = 2;
    private int windowsS10TtlSeconds = 20;
    private int windowsUniqTtlSeconds = 180;

    // Thresholds
    private int thresholdsPerIpS1 = 30;
    private int thresholdsPerIpS10 = 150;
    private int thresholdsGlobalS1 = 2000;
    private int thresholdsGlobalS10 = 10000;
    private int thresholdsPerPathS10 = 3000;
    private int thresholdsUniqIpsPerMinute = 2000;

    // Signals
    private boolean signalsUseDistinctIpSurge = true;
    private boolean signalsCheckSuspiciousUa = true;

    // Extraction & UA hints
    private List<String> ipHeaders = List.of("x-forwarded-for", "x-real-ip");
    private List<String> suspiciousUserAgents = List.of("curl/", "python-requests", "scrapy");
}